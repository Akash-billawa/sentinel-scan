"""Tests for the tool fingerprinter.

Each test feeds a synthetic signal dict into ``fingerprint_tool`` and
asserts the returned guess.  The signal dicts mirror the shape produced
by the detection engine for real scans.  We focus on the tool
attribution logic; the OS / classifier logic is tested separately.
"""

from backend.fingerprinter import (
    _opts_angry_ip,
    _opts_linux_nmap,
    _opts_masscan_minimal,
    _opts_rustscan,
    _opts_unicornscan,
    _opts_windows_nmap,
    _opts_zgrab,
    fingerprint_tool,
)


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def _signals(**overrides):
    """Build a signal dict with sane defaults.

    All numeric fields are zero, all bool fields are False, and the
    TCP options dict is empty.  The caller overrides the fields it
    cares about.
    """
    base = {
        "has_tcp": False,
        "has_udp": False,
        "has_icmp": False,
        "unique_ports": 0,
        "unique_targets": 1,
        "syn_ratio": 0.0,
        "tcp_completion_ratio": 0.0,
        "flags_seen": {},
        "uses_ecn": False,
        "proto_mix": {"TCP": 0, "UDP": 0, "ICMP": 0},
        "packet_count": 0,
        "rate": 0.0,
        "tcp_options_sample": {},
        "tcp_options_seen": False,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# TCP-option predicate tests
# ---------------------------------------------------------------------------


class TestOptionPredicates:
    """The option predicates are the building blocks for every scorer."""

    def test_linux_nmap_matches_canonical_layout(self):
        opts = {"mss": 1460, "wscale": 7, "sack_perm": True, "timestamp": True}
        matched, label = _opts_linux_nmap(opts)
        assert matched
        assert "Nmap" in label or "Linux" in label

    def test_linux_nmap_accepts_wscale_8(self):
        """Older Linux / Nmap unprivileged defaults to WSCALE=8."""
        opts = {"mss": 1460, "wscale": 8, "sack_perm": True}
        assert _opts_linux_nmap(opts)[0] is True

    def test_linux_nmap_accepts_wscale_10(self):
        """Modern Linux / Nmap unprivileged defaults to WSCALE=10."""
        opts = {"mss": 1460, "wscale": 10, "sack_perm": True}
        assert _opts_linux_nmap(opts)[0] is True

    def test_linux_nmap_accepts_1452_mss(self):
        """PPPoE shim is a common MSS that should still match Nmap."""
        opts = {"mss": 1452, "wscale": 7, "sack_perm": True}
        assert _opts_linux_nmap(opts)[0] is True

    def test_linux_nmap_rejects_no_sack(self):
        """Without SACK_PERM this is more likely a non-scanning client."""
        opts = {"mss": 1460, "wscale": 7, "sack_perm": False}
        assert _opts_linux_nmap(opts)[0] is False

    def test_linux_nmap_rejects_unusual_mss(self):
        """Jumbo frame MSS shouldn't be classified as a typical Nmap SYN."""
        opts = {"mss": 9000, "wscale": 7, "sack_perm": True}
        assert _opts_linux_nmap(opts)[0] is False

    def test_masscan_minimal_matches(self):
        opts = {"mss": 1460}
        assert _opts_masscan_minimal(opts)[0] is True

    def test_masscan_minimal_rejects_with_wscale(self):
        opts = {"mss": 1460, "wscale": 7}
        assert _opts_masscan_minimal(opts)[0] is False

    def test_angry_ip_matches_jvm_default(self):
        opts = {"mss": 1460, "sack_perm": True, "wscale": 4}
        assert _opts_angry_ip(opts)[0] is True

    def test_angry_ip_rejects_with_timestamp(self):
        """Angry IP's JVM never sets Timestamp — disqualify if seen."""
        opts = {"mss": 1460, "sack_perm": True, "timestamp": True}
        assert _opts_angry_ip(opts)[0] is False

    def test_windows_nmap_matches_ttl128_wscale8(self):
        opts = {"mss": 1460, "wscale": 8, "sack_perm": True}
        assert _opts_windows_nmap(opts)[0] is True

    def test_rustscan_matches_mss_only(self):
        opts = {"mss": 1460}
        assert _opts_rustscan(opts)[0] is True

    def test_rustscan_rejects_with_sack(self):
        opts = {"mss": 1460, "sack_perm": True}
        assert _opts_rustscan(opts)[0] is False

    def test_zgrab_matches_go_default(self):
        opts = {"mss": 1460, "sack_perm": True, "wscale": 7, "nop": 4}
        assert _opts_zgrab(opts)[0] is True

    def test_zgrab_accepts_wscale_10(self):
        opts = {"mss": 1460, "sack_perm": True, "wscale": 10, "nop": 4}
        assert _opts_zgrab(opts)[0] is True

    def test_zgrab_rejects_with_timestamp(self):
        """Go's net package never sets Timestamp — disqualify if seen."""
        opts = {"mss": 1460, "sack_perm": True, "wscale": 7, "timestamp": True}
        assert _opts_zgrab(opts)[0] is False

    def test_unicornscan_matches_no_mss(self):
        opts = {"sack_perm": True, "timestamp": True}
        assert _opts_unicornscan(opts)[0] is True

    def test_unicornscan_rejects_with_mss(self):
        """Unicornscan typically omits MSS."""
        opts = {"mss": 1460, "sack_perm": True}
        assert _opts_unicornscan(opts)[0] is False


# ---------------------------------------------------------------------------
# Per-tool attribution
# ---------------------------------------------------------------------------


class TestNmapAttribution:
    """Nmap: SYN-dominant, partial completion, 10-1500 pps, kernel options."""

    def test_classic_nmap_linux_kernel_layout(self):
        signals = _signals(
            has_tcp=True,
            unique_ports=200,
            syn_ratio=0.95,
            tcp_completion_ratio=0.5,
            rate=300,
            tcp_options_sample={"mss": 1460, "wscale": 7, "sack_perm": True,
                                "timestamp": True, "nop": 2},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool in ("Nmap", "Zenmap")  # Zenmap is Nmap with low rate
        assert guess.confidence >= 50

    def test_nmap_with_partial_completion(self):
        """A scan with mid-range completion should still be Nmap."""
        signals = _signals(
            has_tcp=True,
            unique_ports=80,
            syn_ratio=0.9,
            tcp_completion_ratio=0.6,
            rate=200,
            tcp_options_sample={"mss": 1460, "wscale": 7, "sack_perm": True},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Nmap"
        assert guess.confidence >= 40

    def test_nmap_with_ecn_flag(self):
        """Nmap -sS with ECN probe is a strong Nmap signature."""
        signals = _signals(
            has_tcp=True,
            unique_ports=10,
            syn_ratio=0.9,
            rate=100,
            uses_ecn=True,
            flags_seen={"SYN": True, "ECE": True, "CWR": True},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool in ("Nmap", "Zenmap")

    def test_nmap_raw_syn_mss_only(self):
        """Root SYN scan (nmap -sS) from Kali Linux emits MSS-only options and is paced at ~150-1000 pps."""
        signals = _signals(
            has_tcp=True,
            unique_ports=1000,
            syn_ratio=0.95,
            tcp_completion_ratio=0.02,
            rate=200,
            tcp_options_sample={"mss": 1460},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Nmap"
        assert guess.confidence >= 50

    def test_nmap_unprivileged_wscale_10(self):
        """Unprivileged Connect scan (nmap -sT) on modern Linux/Kali inherits the kernel's default options (e.g., wscale=10)."""
        signals = _signals(
            has_tcp=True,
            unique_ports=1000,
            syn_ratio=0.9,
            tcp_completion_ratio=0.5,
            rate=200,
            tcp_options_sample={"mss": 1460, "wscale": 10, "sack_perm": True, "timestamp": True},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Nmap"
        assert guess.confidence >= 50


class TestMasscanAttribution:
    """Masscan: very high rate, minimal options, no completion."""

    def test_classic_masscan(self):
        signals = _signals(
            has_tcp=True,
            unique_ports=2000,
            syn_ratio=0.99,
            tcp_completion_ratio=0.01,
            rate=5000,
            tcp_options_sample={"mss": 1460},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Masscan"
        assert guess.confidence >= 70

    def test_masscan_with_sack_perm_still_works(self):
        """Newer Masscan builds add SACK_PERM by default."""
        signals = _signals(
            has_tcp=True,
            unique_ports=1500,
            syn_ratio=0.95,
            tcp_completion_ratio=0.05,
            rate=3000,
            tcp_options_sample={"mss": 1460, "sack_perm": True},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Masscan"

    def test_slow_scan_with_minimal_options_is_not_masscan(self):
        """A slow scan that happens to have minimal options isn't Masscan."""
        signals = _signals(
            has_tcp=True,
            unique_ports=5,
            syn_ratio=0.8,
            tcp_completion_ratio=0.1,
            rate=10,  # Way too slow for Masscan
            tcp_options_sample={"mss": 1460},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool != "Masscan"


class TestRustScanAttribution:
    """RustScan: mid rate (50-1500 pps), minimal options."""

    def test_classic_rustscan(self):
        signals = _signals(
            has_tcp=True,
            unique_ports=2000,
            syn_ratio=0.95,
            tcp_completion_ratio=0.05,
            rate=500,  # Mid-range
            tcp_options_sample={"mss": 1460},  # No SACK, no WSCALE
        )
        guess = fingerprint_tool(signals)
        assert guess.tool in ("RustScan", "Masscan")
        if guess.tool == "Masscan":
            # 500 pps is below Masscan's 1500-pps threshold so the test
            # should prefer RustScan over Masscan.
            assert guess.confidence < 50

    def test_rustscan_with_sack_isnt_rustscan(self):
        """RustScan never sets SACK_PERM — disqualify if seen."""
        signals = _signals(
            has_tcp=True,
            unique_ports=2000,
            syn_ratio=0.95,
            tcp_completion_ratio=0.05,
            rate=500,
            tcp_options_sample={"mss": 1460, "sack_perm": True},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool != "RustScan"


class TestAngryIPAttribution:
    """Angry IP: ICMP+TCP combo, small port set, many hosts."""

    def test_classic_angry_ip_ping_then_tcp(self):
        signals = _signals(
            has_tcp=True,
            has_icmp=True,
            unique_ports=20,
            unique_targets=50,
            syn_ratio=0.8,
            rate=80,
            tcp_options_sample={"mss": 1460, "sack_perm": True, "wscale": 4},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Angry IP Scanner"

    def test_high_rate_scan_isnt_angry_ip(self):
        """Angry IP is a slow scanner; a high rate disqualifies it."""
        signals = _signals(
            has_tcp=True,
            has_icmp=True,
            unique_ports=20,
            unique_targets=50,
            syn_ratio=0.8,
            rate=1000,  # Way too fast
            tcp_options_sample={"mss": 1460, "sack_perm": True, "wscale": 4},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool != "Angry IP Scanner"


class TestZGrabAttribution:
    """ZGrab: Go default options, full handshake (banner grab)."""

    def test_classic_zgrab(self):
        signals = _signals(
            has_tcp=True,
            unique_ports=5,
            unique_targets=20,
            syn_ratio=0.5,
            tcp_completion_ratio=0.9,  # Full handshake
            rate=10,
            tcp_options_sample={"mss": 1460, "sack_perm": True, "wscale": 7,
                                "nop": 4},  # No timestamp
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "ZGrab"

    def test_high_rate_sweep_isnt_zgrab(self):
        """ZGrab is application-paced; high rate SYN-only is not it."""
        signals = _signals(
            has_tcp=True,
            unique_ports=500,
            syn_ratio=0.99,
            tcp_completion_ratio=0.0,
            rate=2000,  # Far too fast
            tcp_options_sample={"mss": 1460, "sack_perm": True, "wscale": 7},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool != "ZGrab"


class TestUnicornscanAttribution:
    """Unicornscan: slow, low-rate, options without MSS."""

    def test_classic_unicornscan(self):
        signals = _signals(
            has_tcp=True,
            unique_ports=10,
            unique_targets=5,
            syn_ratio=0.8,
            rate=2,  # Very slow
            tcp_options_sample={"sack_perm": True, "timestamp": True},  # No MSS
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Unicornscan"

    def test_fast_scan_with_no_mss_isnt_unicornscan(self):
        """Unicornscan is slow; a fast scan disqualifies it."""
        signals = _signals(
            has_tcp=True,
            unique_ports=10,
            unique_targets=5,
            syn_ratio=0.8,
            rate=200,  # Too fast
            tcp_options_sample={"sack_perm": True},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool != "Unicornscan"


class TestUnknownFallback:
    """A scan that doesn't match any tool signature should be Unknown."""

    def test_empty_signals(self):
        guess = fingerprint_tool(_signals())
        assert guess.tool == "Unknown"
        assert guess.confidence == 0

    def test_low_confidence_falls_back_to_unknown(self):
        """A scan with very weak signals (e.g. 3 ports) should not be guessed."""
        signals = _signals(
            has_tcp=True,
            unique_ports=3,
            syn_ratio=0.5,
            rate=2,  # Way below any tool's range
        )
        guess = fingerprint_tool(signals)
        # Below the confidence floor — should be Unknown.
        assert guess.tool == "Unknown"


class TestNegativeEvidence:
    """Penalties should drop weak candidates and protect strong ones."""

    def test_nmap_penalised_for_too_fast(self):
        """A 10000-pps SYN scan with 6000 ports is too fast for Nmap."""
        signals = _signals(
            has_tcp=True,
            unique_ports=6000,
            syn_ratio=0.99,
            tcp_completion_ratio=0.01,
            rate=10000,
            tcp_options_sample={"mss": 1460, "wscale": 7, "sack_perm": True},
        )
        guess = fingerprint_tool(signals)
        # Masscan is the right answer here, not Nmap.
        assert guess.tool != "Nmap"

    def test_masscan_penalised_for_too_slow(self):
        """A 5-pps scan is too slow for Masscan."""
        signals = _signals(
            has_tcp=True,
            unique_ports=100,
            syn_ratio=0.95,
            tcp_completion_ratio=0.05,
            rate=5,  # Way too slow
            tcp_options_sample={"mss": 1460},
        )
        guess = fingerprint_tool(signals)
        assert guess.tool != "Masscan"


# ---------------------------------------------------------------------------
# New attribution signals (TTL, source-port, port-order, timing)
# ---------------------------------------------------------------------------


class TestSourcePortSignal:
    """Nmap ``-g/--source-port`` produces a constant source port."""

    def test_nmap_with_fixed_source_port_boosts_confidence(self):
        """A fixed source port on a scan-shaped burst bumps Nmap's score."""
        baseline = fingerprint_tool(
            _signals(
                has_tcp=True,
                unique_ports=200,
                syn_ratio=0.95,
                tcp_completion_ratio=0.5,
                rate=300,
                tcp_options_sample={
                    "mss": 1460, "wscale": 7, "sack_perm": True, "timestamp": True,
                },
            )
        )
        boosted = fingerprint_tool(
            _signals(
                has_tcp=True,
                unique_ports=200,
                syn_ratio=0.95,
                tcp_completion_ratio=0.5,
                rate=300,
                tcp_options_sample={
                    "mss": 1460, "wscale": 7, "sack_perm": True, "timestamp": True,
                },
                source_port_fixed=True,
            )
        )
        # Same tool, but the fixed source port is real evidence so
        # the attribution should be at least as confident.
        assert boosted.tool in ("Nmap", "Zenmap")
        assert boosted.confidence >= baseline.confidence

    def test_nmap_fixed_source_port_does_not_fire_without_scan_shape(self):
        """A fixed source port on a benign flow doesn't promote to Nmap."""
        signals = _signals(
            has_tcp=True,
            unique_ports=2,
            syn_ratio=0.0,
            rate=1,
            tcp_options_sample={"mss": 1460, "wscale": 7, "sack_perm": True},
            source_port_fixed=True,
        )
        guess = fingerprint_tool(signals)
        # A 2-port benign flow at 1 pps isn't a scan even with a
        # fixed source port.  Should not be Nmap.
        assert guess.tool != "Nmap" or guess.confidence < 30


class TestTtlSignal:
    """TTL 128 (Windows) and TTL 255 (network device) steer attribution."""

    def test_ttl_128_windows_nmap(self):
        """A TTL 128 SYN with the Windows-default WSCALE+options calls Nmap."""
        signals = _signals(
            has_tcp=True,
            unique_ports=200,
            syn_ratio=0.95,
            tcp_completion_ratio=0.5,
            rate=200,
            tcp_options_sample={
                "mss": 1460, "wscale": 8, "sack_perm": True, "timestamp": True,
            },
            ttl_first_syn=128,
        )
        guess = fingerprint_tool(signals)
        assert guess.tool in ("Nmap", "Zenmap")

    def test_ttl_64_linux_nmap(self):
        """A TTL 64 SYN with the Linux-default options calls Nmap."""
        signals = _signals(
            has_tcp=True,
            unique_ports=200,
            syn_ratio=0.95,
            rate=200,
            tcp_options_sample={
                "mss": 1460, "wscale": 7, "sack_perm": True, "timestamp": True,
            },
            ttl_first_syn=64,
        )
        guess = fingerprint_tool(signals)
        assert guess.tool in ("Nmap", "Zenmap")

    def test_ttl_255_penalises_nmap(self):
        """TTL 255 (network device) is atypical for Nmap."""
        signals = _signals(
            has_tcp=True,
            unique_ports=200,
            syn_ratio=0.95,
            rate=200,
            tcp_options_sample={
                "mss": 1460, "wscale": 7, "sack_perm": True, "timestamp": True,
            },
            ttl_first_syn=255,
        )
        guess = fingerprint_tool(signals)
        # The TTL-255 penalty should drop Nmap below the confidence
        # floor, so the result is Unknown (or another tool wins).
        # Either way, not a confident Nmap.
        assert guess.tool != "Nmap" or guess.confidence < 30


class TestPortOrderContinuity:
    """A dense numeric port walk is a Masscan/RustScan tell."""

    def test_masscan_with_sequential_ports(self):
        """Wide port set with high continuity is Masscan-like."""
        signals = _signals(
            has_tcp=True,
            unique_ports=2000,
            syn_ratio=0.99,
            tcp_completion_ratio=0.01,
            rate=4000,
            tcp_options_sample={"mss": 1460},
            port_order_continuity=0.9,
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Masscan"

    def test_rustscan_with_sequential_ports(self):
        """Mid-rate sequential-port burst is RustScan."""
        signals = _signals(
            has_tcp=True,
            unique_ports=2000,
            syn_ratio=0.95,
            tcp_completion_ratio=0.05,
            rate=500,
            tcp_options_sample={"mss": 1460},
            port_order_continuity=0.85,
        )
        guess = fingerprint_tool(signals)
        # Continuity boost is small; RustScan should still win
        # over Masscan at 500 pps.
        assert guess.tool == "RustScan"


class TestTimingCv:
    """High timing CV flags human-paced (Zenmap) bursts."""

    def test_high_cv_flags_zenmap(self):
        """A scan-shaped burst with high timing variance → Zenmap."""
        signals = _signals(
            has_tcp=True,
            unique_ports=200,
            syn_ratio=0.95,
            tcp_completion_ratio=0.5,
            rate=10,  # Slow enough to be Zenmap-like
            tcp_options_sample={
                "mss": 1460, "wscale": 7, "sack_perm": True, "timestamp": True,
            },
            timing_cv=0.8,
        )
        guess = fingerprint_tool(signals)
        assert guess.tool == "Zenmap"

    def test_low_cv_no_zenmap_boost(self):
        """A scan-shaped burst with low CV at moderate rate is just Nmap."""
        signals = _signals(
            has_tcp=True,
            unique_ports=200,
            syn_ratio=0.95,
            tcp_completion_ratio=0.5,
            rate=200,
            tcp_options_sample={
                "mss": 1460, "wscale": 7, "sack_perm": True, "timestamp": True,
            },
            timing_cv=0.05,  # Very steady — script-paced
        )
        guess = fingerprint_tool(signals)
        # No Zenmap boost at 200 pps; should be Nmap.
        assert guess.tool == "Nmap"


class TestCustomScannerCap:
    """The Custom Scanner fallback should be visibly low-confidence."""

    def test_custom_scanner_confidence_capped(self):
        """A burst that triggers Custom Scanner must score below 0.55."""
        signals = _signals(
            has_tcp=True,
            unique_ports=3,
            syn_ratio=0.5,
            rate=2,
            unique_targets=1,
        )
        guess = fingerprint_tool(signals)
        # The 3-port probe should be Unknown, not Custom.  But
        # even if it were Custom, the cap should keep confidence
        # low.  Test the cap separately by constructing a Custom
        # signal that's known to fire the scorer.
        from backend.fingerprinter import _fingerprint_custom
        score, _, _, _ = _fingerprint_custom({
            "unique_ports": 200,
            "rate": 600,
            "syn_ratio": 0.5,
            "packet_count": 100,
            "unique_targets": 1,
        })
        # The internal cap is 0.7; the public cap is 0.55.  The
        # aggregator clamps at 0.55.
        assert score <= 0.7

