# Plan: Port Suricata Detection Rules into SentinelScan

## Goal
Improve SentinelScan's detection accuracy by porting proven Suricata/Emerging Threats scan detection rules into the existing classifier. No external Suricata installation required — the rules run as native Python logic.

## Why Suricata Rules?
- Suricata's ET OPEN ruleset is the industry standard for network scan detection
- Rules encode decades of attacker behavior patterns (Nmap T1-T5 speeds, MSS/window signatures, flag combinations)
- SentinelScan's current classifier only uses flag ratios + port counts — it misses window-size fingerprints, MSS matching, and threshold-based counting that Suricata uses

## What Suricata Rules Detect That SentinelScan Currently Misses

| Suricata Rule | Detection | SentinelScan Current |
|---------------|-----------|---------------------|
| `flags:S; window:1024; tcp.mss:1460` | Nmap SYN scan fingerprint | Only checks syn_ratio > 0.7 |
| `flags:A; window:1024` | Nmap ACK scan | Not detected at all |
| `flags:FPU` | Christmas tree scan | Detected but no window/MSS check |
| `fragbits:M+D` | Fragmented scan | Not detected |
| `threshold: count 20, seconds 70` | Rate-based threshold per source | Uses simple rate_threshold, no per-source tracking |
| UDP `dsize:0` | Empty UDP probes | Only checks "has_udp and unique_ports >= 3" |

## Implementation Plan

### Step 1: Add TCP Window + MSS to PacketRecord and Signals
**Files:** `backend/detector.py`

The Suricata rules match on `window:1024` and `tcp.mss:1460` — Nmap's default SYN scan produces these exact values. SentinelScan already parses TCP options but doesn't expose window size or MSS as signals.

- Add `tcp_window` and `tcp_mss` fields to the signals dict (already available in `PacketRecord.tcp_window` and `PacketRecord.tcp_options["mss"]`)
- Compute aggregate signals: `window_value` (mode of window sizes), `mss_value` (mode of MSS values)
- These enable the SYN scan fingerprint rule

### Step 2: Create `backend/rules.py` — Suricata-Compatible Rule Engine
**New file**

A lightweight rule engine that evaluates Suricata-style detection rules against packet signals. No full Suricata parser needed — just the scan detection subset.

Rules defined as Python dataclasses:
```python
@dataclass
class DetectionRule:
    sid: int                    # Suricata-style signature ID
    name: str                   # Human-readable name (maps to msg:)
    scan_type: str              # Classification label
    priority: int               # 1=high, 2=medium, 3=low
    confidence: float           # 0.0-1.0 base confidence
    classify: Callable          # predicate(signals_dict) -> bool
```

Port these ET OPEN / Nmap detection rules:

| SID | Rule Name | Logic |
|-----|-----------|-------|
| 3400001 | SYN Scan (-sS) fast | flags:S, window:1024, mss:1460, count≥20 in 70s |
| 3400002 | SYN Scan (-sS) slow | flags:S, window:1024, mss:1460, count≥7 in 135s |
| 3400003 | Connect Scan (-sT) | flags:S, window:32120, count≥20 in 70s |
| 3400004 | ACK Scan (-sA) | flags:A only, window:1024, count≥20 in 70s |
| 3400005 | XMAS Scan (-sX) | flags:FPU, count≥3 in 120s |
| 3400006 | Fragmented Scan (-f) | IP fragbits:M+D |
| 3400007 | UDP Scan (-sU) fast | UDP, dsize:0, count≥20 in 70s |
| 3400008 | UDP Scan (-sU) slow | UDP, dsize:0, count≥7 in 135s |
| 3400009 | NULL Scan | TCP, no flags, count≥3 |
| 3400010 | FIN Scan | FIN only (no SYN/ACK), count≥3 |
| 3400011 | Masscan | rate≥1500, syn_ratio>0.8 |
| 3400012 | Service Enum | unique_ports≥30, completion≥0.4 |
| 3400013 | Ping Sweep | ICMP only, unique_targets≥5 |

### Step 3: Update `backend/classifier.py` — Use Rules Engine
**File:** `backend/classifier.py`

Replace the ad-hoc if/elif chain with the rules engine:
1. Import `DetectionRule` list from `rules.py`
2. In `classify()`, iterate rules, collect matching votes
3. Fall through to existing default labels (Tunnel/Proxy, Persistent Connection) for non-scan traffic
4. Keep the existing `ClassificationResult` dataclass unchanged

### Step 4: Add Per-Source Threshold Tracking to Detector
**File:** `backend/detector.py`

The Suricata rules use `threshold:type threshold, track by_src, count N, seconds T`. SentinelScan's current cooldown is per-scan_type, not per-source threshold counting.

- Add `_source_thresholds: Dict[str, List[datetime]]` to track packet timestamps per source IP
- In `_evaluate()`, maintain a sliding window of timestamps per source
- Pass `source_rate_70s` (count in last 70s) and `source_rate_135s` (count in last 135s) as signals
- This enables the slow-scan rules (7 in 135s) that catch Nmap T1-T2

### Step 5: Update Risk Scorer for New Scan Types
**File:** `backend/risk.py`

Add severity ratings for new classifications:
- ACK Scan: 0.70 (stealthy, used for firewall mapping)
- Fragmented Scan: 0.75 (evasion technique)
- NULL Scan: 0.80 (evasion technique)
- Ping Sweep: 0.25 (already exists)

### Step 6: Add Rules Configuration to Settings
**File:** `backend/config.py`

Add `SENTINEL_SCAN_RULES` env var to enable/disable rules by SID:
```
SENTINEL_SCAN_RULES=3400001,3400002,3400003,3400004,3400005
```
Default: all rules enabled.

### Step 7: Tests
**File:** `tests/test_classifier.py` (new), `tests/test_rules.py` (new)

- Unit tests for each detection rule with synthetic signal dicts
- Test that Cloudflare WARP traffic (≤3 ports, single target) is NOT classified as scan
- Test that real Nmap SYN scan (many ports, window:1024, mss:1460) IS classified correctly
- Test ACK scan, XMAS scan, NULL scan, UDP scan detection
- Test threshold counting (7 packets in 135s triggers slow-scan rule)

## Files Modified
| File | Change |
|------|--------|
| `backend/detector.py` | Add window/MSS signals, per-source threshold tracking |
| `backend/rules.py` | **New** — Suricata-compatible detection rules |
| `backend/classifier.py` | Use rules engine instead of ad-hoc if/elif |
| `backend/risk.py` | Add severity for new scan types |
| `backend/config.py` | Add SENTINEL_SCAN_RULES setting |
| `tests/test_classifier.py` | **New** — classifier unit tests |
| `tests/test_rules.py` | **New** — rules engine unit tests |

## Verification
1. Run full test suite: `python -m pytest tests/ -q` — all existing + new tests pass
2. Inject test packets via `/api/engine/inject`:
   - SYN scan pattern: many ports, window:1024 → should detect "SYN Scan"
   - ACK scan pattern: ACK-only flags → should detect "ACK Scan"
   - Cloudflare WARP: 1 port, 200 packets → should be suppressed
3. Verify Kali VM Nmap scan is now detected with correct classification
