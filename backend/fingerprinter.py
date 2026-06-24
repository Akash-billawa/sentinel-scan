"""Tool fingerprinting.

Infers the most likely scanning tool from a few observed characteristics.
The signals are coarse — the goal is to give the operator a hint, not
to definitively attribute the scanner.  The PRD lists the supported
tools and we stick to that set, plus a couple of modern additions
(RustScan, ZGrab, Unicornscan) that show up frequently in real-world
traffic and are easy to distinguish from the classics.

The TCP-options layer is **necessary but never sufficient** on its own.
A non-scanning Linux 4.x/5.x/6.x kernel emits the same
``MSS=1460, NOP, WSCALE=7, NOP, NOP, SACK_PERM, TS×4`` layout that
Nmap uses (Nmap unprivileged mode uses the kernel's own options).  So
option matches multiply the scan-shape score; they never add a flat
bonus that could promote a benign conversation to "Nmap".

Beyond the existing rules this revision adds:

* **Negative evidence** — a candidate is penalised when its signature
  contradicts the observation.  E.g. an "Angry IP" candidate with
  ``rate > 1500 pps`` is clearly not Angry IP, even if some options
  match.  The penalty is bounded so it can fully eliminate a guess.
* **Port-pattern shape** — Masscan and Nmap -p- tend to enumerate
  ports in *numeric order*; random tools and slow scanners do not.
  A burst whose unique ports form a near-continuous numeric interval
  is more likely a wide scan (Masscan / Nmap -p-) than a top-1000
  sweep.
* **TTL discrimination** — different tool families default to
  different initial TTLs (Masscan: 64, Nmap on Windows: 128,
  Unicornscan: 64).  The signals are folded into the candidate scores.
* **Inter-packet timing** — Human-paced (Zenmap, Nmap -T2) vs.
  script-paced (Nmap -T4, Masscan).  We use a coarse band rather than
  exact mean to keep the rule robust to small jitter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


@dataclass
class ToolGuess:
    tool: str
    confidence: float
    reasons: List[str] = field(default_factory=list)          # [+] supporting evidence
    negative_reasons: List[str] = field(default_factory=list) # [-] contradictory evidence


# ---------------------------------------------------------------------------
# TCP-option signature predicates
# ---------------------------------------------------------------------------
#
# Each predicate inspects the SYN-only ``tcp_options_sample`` dict and
# returns ``(matched: bool, label: str)``.  Used by the per-tool rules
# below to gate the option bonus.

# We deliberately accept a *range* of valid options layouts, not a single
# exact tuple.  Real Nmap output is surprisingly varied: Nmap -O sets
# different options per probe, ``--tcp-options`` lets the operator
# override them, and unprivileged scans defer to the kernel which can
# be Linux, macOS, or BSD.  So "Nmap-on-Linux" should match the kernel
# layout AND a Nmap -O layout AND a Nmap --badsum layout.

# Common MSS values for an Ethernet host are 1460 (the dominant case),
# 1380 (PPPoE shim), 1452/1440/1400 (various VPN encaps).  We treat any
# of {1380, 1400, 1440, 1452, 1460} as "looks like a normal SYN" and
# only flag a *very* unusual MSS (e.g. 512, 9000) as a "jumbo / non-std"
# signal.  See p0f.fp for the distribution; >1460 implies a jumbo MTU
# which most scanners don't bother setting.
_COMMON_MSS = {1380, 1400, 1440, 1452, 1460}


def _opts_have_mss(opts: Dict) -> bool:
    mss = opts.get("mss")
    return isinstance(mss, int) and mss in _COMMON_MSS


def _opts_linux_nmap(opts: Dict) -> Tuple[bool, str]:
    """Nmap unprivileged / Nmap on a modern Linux kernel.

    Distinguishing features vs other Linux tools:  SACK_PERM is set,
    WSCALE is in {7, 8, 9, 10}, MSS is a common value (1460, 1452, 1440,
    1400, 1380).  Timestamp is not required (Nmap probes without TS
    still match this).
    """
    if not opts:
        return False, ""
    if not _opts_have_mss(opts):
        return False, ""
    if opts.get("wscale") not in (7, 8, 9, 10):
        return False, ""
    # SACK_PERM is the strongest Nmap signal; without it, this is more
    # likely a non-scanning Linux client.
    if not opts.get("sack_perm"):
        return False, ""
    return True, "MSS+{wscale∈7-10}+SACK_PERM (Nmap / Linux kernel layout)"


def _opts_masscan_minimal(opts: Dict) -> Tuple[bool, str]:
    """Masscan: deliberately minimal option set.

    Masscan emits only MSS (no WSCALE, no SACK, no TS).  Some newer
    builds add SACK_OK by default; WSCALE or Timestamp would be unusual.
    """
    if not opts:
        return False, ""
    if not _opts_have_mss(opts):
        return False, ""
    if opts.get("wscale") is not None or opts.get("timestamp"):
        return False, ""
    return True, "MSS-only options (Masscan's minimal layout)"


def _opts_angry_ip(opts: Dict) -> Tuple[bool, str]:
    """Angry IP Scanner: Java defaults.

    Angry IP is a Java application, so its default socket options
    inherit the JVM's defaults: ``MSS=1460, SACK_PERM, WSCALE=4..7,
    NOP, NOP``.  It does NOT set Timestamp.  We accept the layout
    with or without WSCALE (older Java versions omit it).
    """
    if not opts:
        return False, ""
    if not _opts_have_mss(opts):
        return False, ""
    # Angry IP never sets the Timestamp option.
    if opts.get("timestamp"):
        return False, ""
    # WSCALE, if present, should be in the JVM's typical range.
    wscale = opts.get("wscale")
    if wscale is not None and wscale not in (3, 4, 5, 6, 7):
        return False, ""
    return True, "MSS+Java-default options (Angry IP Scanner layout)"


def _opts_windows_nmap(opts: Dict) -> Tuple[bool, str]:
    """Nmap -sV on a Windows host: TTL 128, WSCALE 8, SACK_PERM.

    Differentiated from generic Nmap by the WSCALE=8 (Windows default)
    combined with the scan-shape signals.
    """
    if not opts:
        return False, ""
    return (
        _opts_have_mss(opts)
        and opts.get("wscale") == 8
        and opts.get("sack_perm") is True,
        "MSS+WSCALE=8+SACK_PERM (Nmap on Windows host)",
    )


def _opts_rustscan(opts: Dict) -> Tuple[bool, str]:
    """RustScan: minimal options like Masscan, but with Timestamp off
    and no SACK.  Emits MSS only, no WSCALE, no SACK, no TS.

    On the wire it's nearly indistinguishable from Masscan — the
    primary fingerprint is in the *rate* (RustScan tops out around
    ``min(rate, N)`` where N is the user's ``-b``/batch flag; typical
    is 50-1000 pps, well below Masscan's 10k+ pps).
    """
    if not opts:
        return False, ""
    return (
        _opts_have_mss(opts)
        and opts.get("wscale") is None
        and not opts.get("sack_perm")
        and not opts.get("timestamp"),
        "MSS-only options, no SACK (RustScan-style)",
    )


def _opts_zgrab(opts: Dict) -> Tuple[bool, str]:
    """ZGrab: Go's default TCP options.

    Go's ``net`` package emits ``MSS=1460, NOP, WSCALE=7, NOP, NOP,
    SACK_PERM, NOP, NOP, NOP, NOP`` — very similar to a Linux kernel,
    but importantly: **no Timestamp** option.  ZGrab is the most
    common Go-based scanner; masscan and nmap always (or almost
    always) set Timestamp; ZGrab never does.

    Differentiation from Nmap/Linux: ``timestamp is False``.
    """
    if not opts:
        return False, ""
    if not _opts_have_mss(opts):
        return False, ""
    if opts.get("timestamp"):
        return False, ""
    if opts.get("wscale") not in (6, 7, 8, 9, 10):
        return False, ""
    if not opts.get("sack_perm"):
        return False, ""
    return True, "MSS+SACK_PERM+WSCALE=6-10+no TS (Go / ZGrab layout)"


def _opts_unicornscan(opts: Dict) -> Tuple[bool, str]:
    """Unicornscan: SYN-only with mostly-empty options, no MSS.

    Unicornscan is unusual in that it does NOT include MSS in its
    probe.  When a SYN has TCP options at all, it's typically a
    timestamp-only or SACK-only layout.  Used as a positive signal
    only when ``mss is None`` AND something else is set.
    """
    if not opts:
        return False, ""
    mss = opts.get("mss")
    if mss is not None:
        return False, ""
    # At least one of: timestamp, sack_perm, wscale
    if not (opts.get("timestamp") or opts.get("sack_perm") or opts.get("wscale") is not None):
        return False, ""
    return True, "TCP options without MSS (Unicornscan-style)"


# ---------------------------------------------------------------------------
# Per-tool scoring rules
# ---------------------------------------------------------------------------
#
# Each tool has a scorer that returns ``(score, reasons, penalties)``.
# The aggregator combines them: a tool's final score is the max of
# ``score`` values from each scorer (so additive signals can stack),
# minus any penalties, clamped to ``[0, max_conf]``.  The chosen
# tool is the highest final score; ties broken by ``max_conf`` then
# by a stable order.
#
# Scoring scale is 0..1 (multiplied by 100 for the API surface).


def _has_scan_shape(s: Dict) -> bool:
    """True if the burst looks like an actual scan (not a benign flow).

    This is the same "is it a scan at all" gate that the rest of the
    engine already trusts; we reuse it so that a benign conversation
    can never get promoted to a tool attribution by options alone.
    """
    if s.get("unique_ports", 0) >= 5 and s.get("syn_ratio", 0) > 0.3:
        return True
    if s.get("unique_targets", 0) >= 10:
        return True
    if s.get("rate", 0) >= 100 and s.get("syn_ratio", 0) > 0.5:
        return True
    if s.get("uses_ecn", False):
        return True
    return False


def _is_paced_for_nmap(s: Dict) -> bool:
    """True if rate is in Nmap's plausible range (10-1500 pps).

    Below 10 pps is too slow for typical Nmap; above 1500 pps is
    almost always Masscan.
    """
    rate = s.get("rate", 0.0)
    return 0.1 < rate <= 1500


def _is_paced_for_zenmap(s: Dict) -> bool:
    """True if the rate is in Zenmap / interactive-Nmap range (< 30 pps).

    Zenmap is a GUI, so the typical rate is the one a human clicks
    through.  A burst at exactly 30 pps is more likely Nmap -T2 than
    Zenmap.
    """
    return 0.05 < s.get("rate", 0.0) < 25


def _is_paced_for_masscan(s: Dict) -> bool:
    """True if the rate is in Masscan's plausible range (>= 1500 pps).

    Masscan's signature is its high rate.  Without it we cannot
    reliably call a SYN scan "Masscan".
    """
    return s.get("rate", 0.0) >= 1500


def _is_paced_for_rustscan(s: Dict) -> bool:
    """True if the rate is in RustScan's plausible range (50-1500 pps)."""
    rate = s.get("rate", 0.0)
    return 50 <= rate < 1500


def _narrow_port_set(s: Dict) -> bool:
    """Nmap's default top-1000 + targeted sets hit ≤ ~1500 ports."""
    return 0 < s.get("unique_ports", 0) <= 1500


def _wide_port_set(s: Dict) -> bool:
    """Masscan / Nmap -p- hit many more ports (≥ 1500)."""
    return s.get("unique_ports", 0) >= 1500


def _opts_match(opts: Dict, predicate: Callable[[Dict], Tuple[bool, str]]) -> Tuple[bool, str]:
    """Run a TCP-option predicate, suppressing exceptions defensively."""
    try:
        return predicate(opts)
    except Exception:
        return False, ""


# --- Per-tool scorers ------------------------------------------------------


def _fingerprint_nmap(s: Dict) -> Tuple[float, List[str], List[str], List[Tuple[str, float]]]:
    """Score for Nmap (and any non-masscan, non-scripted scanner)."""
    score, reasons, negative_reasons = 0.0, [], []
    penalties: List[Tuple[str, float]] = []

    # Scan-shape base — the things that *actually* distinguish a port
    # scan from a long-lived conversation.
    if 0.05 < s.get("syn_ratio", 0) and s.get("unique_ports", 0) >= 5:
        score += 0.30
        reasons.append(f"SYN ratio {s.get('syn_ratio', 0):.0%}, {s.get('unique_ports', 0)} ports")
    if s.get("uses_ecn", False):
        score += 0.20
        reasons.append("ECN/CWR flag usage")
    if 0.4 < s.get("tcp_completion_ratio", 0) < 0.95 and s.get("unique_ports", 0) >= 20:
        score += 0.15
        reasons.append("partial handshake completion")
    if _is_paced_for_nmap(s):
        score += 0.10
        reasons.append("human-paced timing")
    # ``_narrow_port_set`` fires on any ``1 <= ports <= 1500`` burst,
    # which used to give a free +0.05 to every scan that didn't blow
    # past Nmap's top-1000 default.  Combined with the timing bonus
    # above, a 3-port probe at 2 pps was scoring above the 15% floor
    # and getting called Nmap.  Require the burst to also look like
    # a scan (>= 5 ports OR ECN probing) so a hand-rolled single-port
    # probe doesn't get attributed.
    if _narrow_port_set(s) and (
        s.get("unique_ports", 0) >= 5 or s.get("uses_ecn", False)
    ):
        score += 0.05
        reasons.append("moderate port set")
    # Source-port discriminator: Nmap's ``-g/--source-port`` flag
    # produces a constant source port.  Real kernel-allocated
    # ephemeral ports vary, so a fixed source port is a strong Nmap
    # tell.  We require the burst to look like a scan first so a
    # long-lived client connecting from :443 doesn't trigger this.
    if s.get("source_port_fixed") and _has_scan_shape(s):
        score += 0.10
        reasons.append("fixed source port (Nmap -g/--source-port)")

    # Option bonus: only if we ALSO have scan shape.  Without scan
    # shape, cap at 0.5 so a normal Linux client isn't called Nmap.
    opts = s.get("tcp_options_sample") or {}
    matched_linux, label_linux = _opts_match(opts, _opts_linux_nmap)
    matched_win, label_win = _opts_match(opts, _opts_windows_nmap)
    matched_raw, label_raw = _opts_match(opts, _opts_masscan_minimal)  # MSS-only
    if matched_linux:
        reasons.append(label_linux)
        if _has_scan_shape(s):
            score = min(score * 1.3, 0.95)
        else:
            # Options alone: cap so this stays "probably Nmap", not a
            # confident Nmap attribution.  Capped base of 0.45.
            score = min(0.45, 0.15 + 0.10 * (1 if opts.get("wscale") else 0)
                        + 0.10 * (1 if opts.get("sack_perm") else 0))
    elif matched_win:
        reasons.append(label_win)
        if _has_scan_shape(s):
            score = min(score * 1.3, 0.95)
        else:
            score = min(0.45, 0.15 + 0.10 * (1 if opts.get("wscale") else 0)
                        + 0.10 * (1 if opts.get("sack_perm") else 0))
    elif matched_raw:
        # MSS-only is also the standard layout for Nmap raw SYN scan (root).
        reasons.append("MSS-only options (Nmap raw SYN layout)")
        if _has_scan_shape(s):
            score = min(score * 1.25, 0.95)

    # Negative evidence: a high-rate scan with a wide port set is
    # unlikely to be Nmap.  Nmap's defaults don't sustain >1500 pps.
    if s.get("rate", 0) > 1500 and s.get("unique_ports", 0) > 5000:
        penalties.append(("nmap-too-fast-for-defaults", 0.40))
        reasons.append("rate too high for default Nmap timing")
    if opts.get("wscale") is not None and opts.get("sack_perm") is None:
        # WSCALE without SACK is rare for Nmap (unprivileged mode defers
        # to the kernel which sets both).  Common for Masscan/RustScan.
        penalties.append(("no-sack-with-wscale", 0.15))
        reasons.append("WSCALE present without SACK (atypical for Nmap)")
    # TTL discrimination: TTL 255 is what network gear and embedded
    # devices use; if a scan claims to be Nmap with a TTL of 255
    # it's almost certainly a misattribution.  TTL 128 (Windows) is
    # consistent with Nmap -sV on a Windows host, so we don't
    # penalise that direction.
    if s.get("ttl_first_syn") == 255:
        penalties.append(("nmap-ttl-network-device", 0.30))
        reasons.append("TTL 255 (network device, atypical for Nmap)")

    return score, reasons, negative_reasons, penalties


def _fingerprint_zenmap(s: Dict) -> Tuple[float, List[str], List[str], List[Tuple[str, float]]]:
    """Zenmap = Nmap GUI; identical network behaviour.

    We only return Zenmap (not Nmap) when the timing profile is
    *interactive* — a heuristic for human-driven use.  The underlying
    scorer is the Nmap one, so the reasons list is shared.

    Two signals earn the Zenmap boost:

    * **Low rate (< 25 pps)** — a human can't generate more than this
      with a GUI, so anything faster is almost certainly a CLI Nmap
      run.  This is the same heuristic the old code used; it has the
      advantage of being testable without per-packet timing.
    * **High timing CV (> 0.5)** — the new ``timing_cv`` signal: a
      coefficient of variation > 0.5 on inter-packet deltas is what
      you see when a human is clicking "next host" between rounds
      of Nmap.  Either signal alone is enough; we don't require both
      so a very slow batch run still gets tagged.
    """
    base, reasons, negative_reasons, penalties = _fingerprint_nmap(s)
    rate = s.get("rate", 0.0)
    cv = s.get("timing_cv", 0.0)
    zenmap_timing = (0.05 < rate < 25) or cv > 0.5
    if base > 0.3 and zenmap_timing:
        reasons.append("low-rate interactive timing")
        return min(base + 0.10, 0.90), reasons, negative_reasons, penalties
    # No interactive timing evidence — don't add Zenmap to the
    # candidate list at all.  Nmap will get attributed instead.
    # Returning a zero score makes ``fingerprint_tool`` skip Zenmap
    # in the aggregator (see the ``score <= 0 and not penalties``
    # gate), which is what we want: a CLI Nmap run at 200 pps should
    # attribute to Nmap, not to Zenmap-by-virtue-of-list-order.
    return 0.0, reasons, negative_reasons, penalties


def _fingerprint_masscan(s: Dict) -> Tuple[float, List[str], List[str], List[Tuple[str, float]]]:
    """Masscan signature: high rate, minimal options, low completion."""
    score, reasons, negative_reasons = 0.0, [], []
    penalties: List[Tuple[str, float]] = []

    if _is_paced_for_masscan(s):
        score += 0.50
        reasons.append(f"very high rate ({s['rate']:.0f} pps)")
    if s.get("syn_ratio", 0) > 0.85 and s.get("tcp_completion_ratio", 0) < 0.1:
        score += 0.20
        reasons.append("SYN-dominant, no completion")
    if _wide_port_set(s):
        score += 0.15
        reasons.append(f"{s['unique_ports']} unique ports")
    # Port-order continuity: Masscan walks ports in numeric order
    # and emits the destinations faster than the kernel allocator
    # can randomise.  A burst whose unique ports form a dense
    # numeric run AND spans many ports is a strong Masscan tell —
    # we boost the score so a slow rate-limited Masscan run (e.g.
    # --rate 1000) still gets attributed correctly.
    if (
        s.get("port_order_continuity", 0.0) > 0.7
        and s.get("unique_ports", 0) >= 500
    ):
        score += 0.10
        reasons.append("ports probed in near-continuous numeric order")
    # TTL discriminator: Masscan defaults to TTL 64 (the Linux /
    # BSD default).  A burst with TTL 128 is more likely a Windows
    # tool (Nmap -sV on Windows); a burst with TTL 255 is a network
    # device.  Neither is impossible for Masscan, but it's worth a
    # soft bias toward Masscan when the TTL matches its default.
    if s.get("ttl_first_syn") == 64:
        score += 0.05
        reasons.append("TTL 64 (Masscan default)")

    opts = s.get("tcp_options_sample") or {}
    # Option discriminator: only *drop* Masscan score if WSCALE or TS
    # is present.  SACK_PERM is fine (newer Masscan builds).
    if opts.get("wscale") is not None or opts.get("timestamp"):
        penalties.append(("masscan-atypical-options", 0.50))
        reasons.append("options include WSCALE/TS (atypical for Masscan)")
    else:
        matched, label = _opts_match(opts, _opts_masscan_minimal)
        if matched:
            reasons.append(label)
            score = min(score * 1.2, 0.95)

    # Negative: Masscan is fast.  A slow burst isn't Masscan.
    if s.get("rate", 0) < 100 and s.get("unique_ports", 0) < 1000:
        penalties.append(("masscan-too-slow", 0.40))
        reasons.append("rate too low for Masscan")

    return min(score, 0.95), reasons, negative_reasons, penalties


def _fingerprint_angry(s: Dict) -> Tuple[float, List[str], List[str], List[Tuple[str, float]]]:
    """Angry IP Scanner signature: small port set, many hosts, ICMP+TCP."""
    score, reasons, negative_reasons = 0.0, [], []
    penalties: List[Tuple[str, float]] = []

    if s.get("has_icmp", False) and s.get("has_tcp", False):
        score += 0.40
        reasons.append("ping + TCP probe combo")
    if 0 < s.get("unique_ports", 0) <= 30 and s.get("unique_targets", 0) >= 5:
        score += 0.30
        reasons.append("small port set, many hosts")
    if 0 < s.get("rate", 0) < 200 and s.get("syn_ratio", 0) > 0.6:
        score += 0.15
        reasons.append("fast-but-modest SYN-leaning probes")

    # Options: Java defaults.  Note Timestamp-on disqualifies this
    # candidate (Angry IP's JVM never sets TS).
    opts = s.get("tcp_options_sample") or {}
    matched, label = _opts_match(opts, _opts_angry_ip)
    if matched:
        reasons.append(label)
        score = min(score + 0.05, 0.90)
    elif opts.get("timestamp"):
        # TS-on contradicts the Angry IP default; soften the score.
        penalties.append(("angry-timestamp-on", 0.25))
        reasons.append("Timestamp option set (atypical for Angry IP)")

    # Negative: Angry IP is a slow scanner.  Very high rate or huge
    # port set contradicts its design.
    if s.get("rate", 0) > 500:
        penalties.append(("angry-too-fast", 0.30))
        reasons.append("rate too high for Angry IP")
    if s.get("unique_ports", 0) > 200:
        penalties.append(("angry-too-many-ports", 0.20))
        reasons.append("port set too large for Angry IP")

    return min(score, 0.9), reasons, negative_reasons, penalties


def _fingerprint_rustscan(s: Dict) -> Tuple[float, List[str], List[str], List[Tuple[str, float]]]:
    """RustScan signature: mid rate, minimal options, Nmap passthrough.

    RustScan is unique in being a *front-end* to Nmap: it sends its own
    fast SYN burst (rate 50-1500 pps, MSS-only options) and then
    hands the results to Nmap for service/version detection.  So a
    burst that looks like "Masscan but slower" is RustScan.

    RustScan operates exclusively over TCP SYN — a pure UDP burst or
    ICMP sweep cannot be RustScan.  The ``has_tcp`` gate prevents
    misattribution when high-rate UDP/ICMP traffic falls in RustScan's
    pacing range (see test_udp_burst_is_not_rustscan).
    """
    if not s.get("has_tcp", False):
        return (0.0, [], [], [])

    score, reasons, negative_reasons = 0.0, [], []
    penalties: List[Tuple[str, float]] = []

    if _is_paced_for_rustscan(s):
        score += 0.40
        reasons.append(f"mid-range rate ({s['rate']:.0f} pps)")
    if s.get("syn_ratio", 0) > 0.85 and s.get("tcp_completion_ratio", 0) < 0.1:
        score += 0.20
        reasons.append("SYN-dominant, no completion")
    if _wide_port_set(s):
        score += 0.10
        reasons.append(f"{s['unique_ports']} unique ports")
    # Port-order continuity: like Masscan, RustScan walks ports in
    # numeric order.  We only apply this when the rate is also in
    # RustScan's range so a high-rate Masscan run with sequential
    # ports doesn't get pulled toward RustScan.
    if (
        _is_paced_for_rustscan(s)
        and s.get("port_order_continuity", 0.0) > 0.7
        and s.get("unique_ports", 0) >= 500
    ):
        score += 0.05
        reasons.append("ports probed in near-continuous numeric order")

    opts = s.get("tcp_options_sample") or {}
    matched, label = _opts_match(opts, _opts_rustscan)
    if matched:
        reasons.append(label)
        score = min(score * 1.2, 0.90)
    # SACK_PERM is the strongest negative for RustScan — its minimal
    # options layout never sets SACK.  This is the test the original
    # scorer missed: with ``sack_perm=True`` we used to attribute the
    # burst to RustScan because WSCALE/TS weren't set, even though
    # the SACK option alone is enough to disqualify it.
    if opts.get("sack_perm"):
        penalties.append(("rustscan-sack-present", 0.45))
        reasons.append("SACK_PERM set (atypical for RustScan)")
    if opts.get("wscale") is not None or opts.get("timestamp"):
        penalties.append(("rustscan-atypical-options", 0.30))
        reasons.append("options include WSCALE/TS (atypical for RustScan)")

    # Negative: too slow is Nmap, too fast is Masscan.
    if s.get("rate", 0) < 30:
        penalties.append(("rustscan-too-slow", 0.30))
        reasons.append("rate too low for RustScan")
    if s.get("rate", 0) >= 1500:
        penalties.append(("rustscan-too-fast", 0.40))
        reasons.append("rate too high for RustScan (Masscan range)")
    if s.get("unique_ports", 0) < 1500:
        penalties.append(("rustscan-narrow-port-set", 0.25))
        reasons.append("narrow port set (atypical for RustScan)")

    return min(score, 0.90), reasons, negative_reasons, penalties


def _fingerprint_zgrab(s: Dict) -> Tuple[float, List[str], List[str], List[Tuple[str, float]]]:
    """ZGrab signature: Go default TCP options, SACK_PERM on, TS off.

    ZGrab is application-layer (HTTP/TLS/SSH banners) but its
    transport layer is a Go ``net.Dial`` so it looks like a generic
    client.  The tell is the *missing* Timestamp option on a SYN
    that otherwise has full SACK+WSCALE — typical of long-lived Go
    HTTPS clients.
    """
    score, reasons, negative_reasons = 0.0, [], []
    penalties: List[Tuple[str, float]] = []

    opts = s.get("tcp_options_sample") or {}
    opts_match, opts_label = _opts_match(opts, _opts_zgrab)
    # ZGrab is a banner-grab tool — it completes the handshake to
    # exchange an HTTP request or TLS ClientHello.  We require some
    # evidence of that (a partial/full handshake, or the Go options
    # signature, or several distinct targets) before any of the
    # ZGrab bonuses fire.  Without this gate, a low-rate
    # single-target probe over a small port set (e.g. an operator
    # running ``curl`` against a few ports) gets misattributed to
    # ZGrab, drowning out the actual Unknown.
    banner_grab_evidence = (
        s.get("tcp_completion_ratio", 0) >= 0.3
        or opts_match
        or s.get("unique_targets", 0) >= 5
    )

    if (
        banner_grab_evidence
        and s.get("has_tcp", False)
        and 1 <= s.get("unique_ports", 0) <= 30
    ):
        score += 0.30
        reasons.append("small targeted port set")
    # The "low rate" signal is only meaningful when we have a real
    # probe to attribute.  Without it, *every* rate-zero / empty
    # burst would land on ZGrab, drowning out the actual Unknown
    # answer (see test_empty_signals).  Gate it on the small port
    # set we already validated.
    if (
        banner_grab_evidence
        and 1 <= s.get("unique_ports", 0) <= 30
        and s.get("rate", 0) < 50
    ):
        score += 0.15
        reasons.append("low rate (application-paced)")
    if (
        banner_grab_evidence
        and 1 <= s.get("unique_ports", 0) <= 30
        and s.get("tcp_completion_ratio", 0) >= 0.5
    ):
        score += 0.20
        reasons.append("full handshake completion (banner grab)")

    if opts_match:
        reasons.append(opts_label)
        score = min(score * 1.25, 0.85)

    # Negative: high-rate SYN-only is not ZGrab.  ZGrab always
    # completes handshakes and rarely scans more than a handful of
    # ports per host.
    if s.get("rate", 0) > 200 and s.get("tcp_completion_ratio", 0) < 0.2:
        penalties.append(("zgrab-too-fast", 0.30))
        reasons.append("rate too high for ZGrab's banner-grab model")
    if s.get("unique_ports", 0) > 200:
        penalties.append(("zgrab-too-many-ports", 0.20))
        reasons.append("port set too large for ZGrab")

    return min(score, 0.85), reasons, negative_reasons, penalties


def _fingerprint_unicornscan(s: Dict) -> Tuple[float, List[str], List[str], List[Tuple[str, float]]]:
    """Unicornscan signature: very low rate, TCP options without MSS.

    Unicornscan is a low-and-slow, payload-aware scanner.  Its SYN
    options are atypical: MSS is often omitted, but SACK/Timestamp
    may appear.  Rate is in the single-digits pps range.
    """
    score, reasons, negative_reasons = 0.0, [], []
    penalties: List[Tuple[str, float]] = []

    opts = s.get("tcp_options_sample") or {}
    opts_match, opts_label = _opts_match(opts, _opts_unicornscan)
    # The "slow low-rate scan" bonus was firing on every quiet burst
    # (anything in 0.1–20 pps), which made Unicornscan swallow a lot
    # of small / incidental traffic.  Gate it on something that looks
    # like a deliberate probe — either enough distinct ports to call
    # it a scan, or the MSS-less options signature Unicornscan is
    # actually known for.  Either signal alone is enough; we don't
    # require both so a slow targeted probe with the right options
    # still gets attributed correctly.
    has_scan_shape = s.get("unique_ports", 0) >= 5
    if (has_scan_shape or opts_match) and 0.1 < s.get("rate", 0) < 20:
        score += 0.30
        reasons.append("slow low-rate scan")
    if s.get("unique_ports", 0) >= 5 and s.get("unique_targets", 0) >= 2:
        score += 0.15
        reasons.append("multi-port, multi-target")

    if opts_match:
        reasons.append(opts_label)
        score = min(score * 1.3, 0.85)

    # Negative: a high rate is not Unicornscan.
    if s.get("rate", 0) > 100:
        penalties.append(("unicornscan-too-fast", 0.40))
        reasons.append("rate too high for Unicornscan")

    return min(score, 0.85), reasons, negative_reasons, penalties


def _fingerprint_custom(s: Dict) -> Tuple[float, List[str], List[str], List[Tuple[str, float]]]:
    """Anything that doesn't match a known tool well.

    We still emit a *guess* with a low confidence so the operator sees
    something — but never above 0.55 (capped by ``_GUESSERS``) so the
    dashboard marks it as low-confidence.  The conditions below are
    deliberately conservative: a Custom guess should only fire on
    something that *looks* like a scan but matches no known
    fingerprint.  A weak signal like "3 ports, syn_ratio 0.5" is
    more accurately reported as Unknown — admitting we don't know is
    better than mislabeling a benign-looking flow as a scanner.
    """
    score, reasons, negative_reasons = 0.0, [], []
    penalties: List[Tuple[str, float]] = []

    if s.get("unique_ports", 0) >= 10 and s.get("rate", 0) < 50:
        score += 0.30
        reasons.append("slow, low-rate scan")
    # Targeted multi-target probe: a small port set against several
    # distinct hosts.  Requires both a non-trivial port set AND
    # multiple targets so a single 3-port probe against a single
    # host doesn't get called a "Custom scanner" — that's more
    # honestly reported as Unknown.
    if (
        0.2 < s.get("syn_ratio", 0) < 0.8
        and 2 <= s.get("unique_ports", 0) < 10
        and s.get("unique_targets", 0) >= 2
    ):
        score += 0.20
        reasons.append("targeted multi-host probe")
    if s.get("packet_count", 0) < 50 and s.get("unique_targets", 0) >= 3:
        score += 0.20
        reasons.append("low-volume, multi-target")
    if s.get("unique_ports", 0) >= 100 and s.get("rate", 0) >= 500:
        # Could be a home-rolled fast scanner.
        score += 0.20
        reasons.append("wide port set, fast rate")
    return min(score, 0.7), reasons, negative_reasons, penalties


# Ordered most-specific first; the first scorer with a positive score
# wins unless a later scorer has a strictly higher final score.
_GUESSERS: List[Tuple[str, Callable, float]] = [
    # (name, scorer, max_confidence)
    ("Zenmap", _fingerprint_zenmap, 0.90),
    ("Nmap", _fingerprint_nmap, 0.95),
    ("Masscan", _fingerprint_masscan, 0.95),
    ("RustScan", _fingerprint_rustscan, 0.90),
    ("ZGrab", _fingerprint_zgrab, 0.85),
    ("Unicornscan", _fingerprint_unicornscan, 0.85),
    ("Angry IP Scanner", _fingerprint_angry, 0.90),
    # Custom Scanner is the explicit fallback: "we don't know what this
    # is, but it's clearly a scanner of some sort".  Capped at 0.55
    # (down from 0.70) so the dashboard surfaces it as a low-confidence
    # guess and the operator knows to investigate rather than trust
    # the label.  A 0.70 cap was making a real "we don't know" look
    # almost as confident as a confident ZGrab.
    ("Custom Scanner", _fingerprint_custom, 0.55),
]

# Confidence floor below which we report "Unknown" instead of a
# guess.  Picking a tool with < 15% confidence is more misleading
# than admitting we don't know.
_CONFIDENCE_FLOOR = 15.0


def fingerprint_tool(signals: Dict) -> ToolGuess:
    """Pick the best tool given a signal dict.

    Each scorer returns ``(score, reasons, penalties)``.  Final score
    is ``clamp(score - sum(penalties), 0, max_conf)`` scaled to 0..100.
    The chosen tool is the highest final score; ties broken by the
    list order (most-specific first).  If every candidate's final
    confidence falls below ``_CONFIDENCE_FLOOR``, we return
    ``("Unknown", 0.0, [...])`` with the strongest reasons for the
    operator to read.
    """
    candidates: List[ToolGuess] = []
    fallback_reasons: List[str] = []
    fallback_negative_reasons: List[str] = []
    for name, fn, max_conf in _GUESSERS:
        score, reasons, negative_reasons, penalties = fn(signals)
        if score <= 0 and not penalties:
            continue
        # Sum penalties (defensive: a buggy scorer should not tank the
        # result past zero; we clamp at the end).
        total_penalty = sum(p for _, p in penalties)
        # Normalize: score is 0..1; scale to 0..100 then subtract the
        # penalty (in 0..100 units, with the same conventions).
        final = max(0.0, min(score * 100.0 - total_penalty * 100.0, max_conf * 100.0))
        if final > 0:
            candidates.append(ToolGuess(name, round(final, 1), list(reasons), list(negative_reasons)))
        else:
            # Keep the strongest reason text in case we end up Unknown.
            if reasons and len(reasons) > len(fallback_reasons):
                fallback_reasons = list(reasons)
            if negative_reasons and len(negative_reasons) > len(fallback_negative_reasons):
                fallback_negative_reasons = list(negative_reasons)

    if not candidates:
        return ToolGuess("Unknown", 0.0, fallback_reasons or ["no matching tool signature"])

    candidates.sort(key=lambda g: g.confidence, reverse=True)
    top = candidates[0]
    if top.confidence < _CONFIDENCE_FLOOR:
        return ToolGuess(
            "Unknown", 0.0,
            fallback_reasons or top.reasons or ["no matching tool signature"],
            fallback_negative_reasons or top.negative_reasons or [],
        )
    return top
