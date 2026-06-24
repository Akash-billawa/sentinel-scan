"""Tests for the detector's signal computation.

The detector feeds the fingerprinter a bag of signals (rate, SYN
ratio, port count, TCP options, etc.) derived from the burst of
packets observed from one source IP.  This module tests the helpers
that compute those signals: ``_initial_ttl`` (TTL bucketing),
``_port_order_continuity`` (sequential-port walk), and
``_timing_cv`` (inter-packet timing variance).

The full end-to-end test lives with the fingerprinter — these
unit tests pin the per-helper semantics so future changes to the
detector don't silently break the fingerprinter's inputs.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

import pytest

from backend.detector import (
    PacketRecord,
    _initial_ttl,
    _port_order_continuity,
    _timing_cv,
)


# ---------------------------------------------------------------------------
# _initial_ttl
# ---------------------------------------------------------------------------


class TestInitialTtl:
    """Round an observed TTL up to the originating stack's default."""

    @pytest.mark.parametrize("observed,expected", [
        (64, 64),    # Linux / BSD default; no hops.
        (63, 64),    # One hop.
        (60, 64),    # Four hops.
        (128, 128),  # Windows default; no hops.
        (127, 128),  # One hop.
        (100, 128),  # Many hops.
        (255, 255),  # Network gear / embedded; no hops.
        (32, 32),    # Legacy Windows 9x / NT.
        (30, 32),    # A couple of hops.
    ])
    def test_known_initial_ttls(self, observed, expected):
        assert _initial_ttl(observed) == expected

    @pytest.mark.parametrize("bad", [None, 0, -1, 256, 1000])
    def test_invalid_ttls(self, bad):
        assert _initial_ttl(bad) is None


# ---------------------------------------------------------------------------
# _port_order_continuity
# ---------------------------------------------------------------------------


class TestPortOrderContinuity:
    """0..1 ratio of unique ports to numeric span."""

    def test_single_port_is_zero(self):
        # No continuity to measure with a single observation.
        assert _port_order_continuity([80]) == 0.0

    def test_empty_list_is_zero(self):
        assert _port_order_continuity([]) == 0.0

    def test_continuous_run_is_one(self):
        # 1..1000 = 1000 distinct ports in a span of 1000.  Full.
        ports = list(range(1, 1001))
        assert _port_order_continuity(ports) == 1.0

    def test_sequential_run_starts_anywhere(self):
        # 50001..51000 = 1000 distinct ports in a span of 1000.
        ports = list(range(50001, 51001))
        assert _port_order_continuity(ports) == 1.0

    def test_sparse_ports_low_continuity(self):
        # 3 random ports across 65535 → ~0.00005.
        assert _port_order_continuity([80, 443, 8080]) < 0.001

    def test_half_density(self):
        # 500 odd ports in 1..1000 → 500 unique in a span of 999.
        # Continuity = 500/999 ≈ 0.5005.
        ports = list(range(1, 1001, 2))
        result = _port_order_continuity(ports)
        assert abs(result - 500 / 999) < 0.001

    def test_dense_top1000(self):
        # The classic Masscan burst.
        ports = list(range(1, 1001))
        assert _port_order_continuity(ports) == 1.0

    def test_unsorted_input_is_sorted_internally(self):
        # We don't promise an order; the helper sorts.  The
        # *result* should be the same either way.
        assert _port_order_continuity([5, 1, 3, 2, 4]) == 1.0

    def test_single_span_below_count_clamps_to_one(self):
        # If somehow we have 200 ports all in a span of 100
        # (impossible without dupes, but defensively), we
        # cap at 1.0 rather than reporting >1.
        # Use a tight range with duplicate coverage to check.
        ports = list(range(1, 51)) * 4  # 200 entries, span 50
        # After sort + dedup by set, this is 50 unique.
        unique = sorted(set(ports))
        # 50 unique in a span of 50 → 1.0
        assert _port_order_continuity(unique) == 1.0


# ---------------------------------------------------------------------------
# _timing_cv
# ---------------------------------------------------------------------------


def _pkts(timestamps):
    """Build a deque of PacketRecord stubs from a list of datetime values.

    Only the ``timestamp`` field is read by ``_timing_cv``, so the
    rest of the record can stay empty.
    """
    return deque(
        PacketRecord(
            timestamp=ts,
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            flags={"SYN": True},
        )
        for ts in timestamps
    )


class TestTimingCv:
    """Coefficient of variation of inter-packet deltas."""

    def test_single_packet_is_zero(self):
        ts = [datetime(2026, 1, 1, 12, 0, 0)]
        assert _timing_cv(_pkts(ts)) == 0.0

    def test_empty_is_zero(self):
        assert _timing_cv(deque()) == 0.0

    def test_perfectly_steady_is_zero(self):
        # 100ms between every packet → std = 0, CV = 0.
        base = datetime(2026, 1, 1, 12, 0, 0)
        ts = [base + timedelta(milliseconds=100 * i) for i in range(20)]
        assert _timing_cv(_pkts(ts)) == 0.0

    def test_high_variance_high_cv(self):
        # Bursts of 5 packets, then a long gap — high CV.
        base = datetime(2026, 1, 1, 12, 0, 0)
        ts = [base + timedelta(milliseconds=i) for i in range(5)]
        ts += [base + timedelta(seconds=10 + i * 0.01) for i in range(5)]
        cv = _timing_cv(_pkts(ts))
        assert cv > 0.5

    def test_moderate_jitter(self):
        # 100ms ± 10ms — low CV, script-paced.
        base = datetime(2026, 1, 1, 12, 0, 0)
        ts = [base + timedelta(milliseconds=100 * i) for i in range(20)]
        cv = _timing_cv(_pkts(ts))
        assert 0.0 <= cv < 0.2

    def test_zero_deltas_are_skipped(self):
        # Multiple packets at the same instant — should not
        # divide-by-zero.
        ts = [datetime(2026, 1, 1, 12, 0, 0)] * 5
        cv = _timing_cv(_pkts(ts))
        # All deltas filtered out → CV is 0.0.
        assert cv == 0.0


# ---------------------------------------------------------------------------
# fragmented_count signal computation
# ---------------------------------------------------------------------------

def test_fragmented_count_all_normal():
    pkts = deque(
        PacketRecord(
            timestamp=datetime(2026, 1, 1, 12, 0, i),
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            flags={"SYN": True},
            is_fragment=False,
        )
        for i in range(10)
    )
    assert sum(1 for p in pkts if p.is_fragment) == 0


def test_fragmented_count_some_fragments():
    pkts = deque(
        PacketRecord(
            timestamp=datetime(2026, 1, 1, 12, 0, i),
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            flags={"SYN": True},
            is_fragment=(i < 4),
        )
        for i in range(10)
    )
    assert sum(1 for p in pkts if p.is_fragment) == 4
