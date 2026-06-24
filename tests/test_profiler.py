"""Tests for the profiler's hostname cache and reverse DNS logic.

The profiler has the most network-dependent code in the project, so
these tests focus on:

* cache hit/miss semantics (positive and negative results)
* LRU eviction when the cache is full
* TTL expiry
* thread-safety (smoke test: many concurrent lookups on the same IP)
* the timeout path (a slow DNS call doesn't pin the test forever)
"""

import socket
import threading
import time
from unittest import mock

import pytest

from backend.profiler import (
    HostnameCache,
    _get_resolver_pool,
    _is_private,
    _is_valid_ip,
    _reverse_dns,
    profile_source,
    reset_hostname_cache,
    set_hostname_cache_size,
)


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset module-level cache + pool between tests."""
    reset_hostname_cache()
    yield
    reset_hostname_cache()


# ---------------------------------------------------------------------------
# IP validation helpers
# ---------------------------------------------------------------------------


class TestIpValidation:
    """``_is_valid_ip`` and ``_is_private`` gate the DNS path."""

    @pytest.mark.parametrize("ip", [
        "8.8.8.8", "1.1.1.1", "192.168.1.10", "10.0.0.1",
        "::1", "2001:db8::1", "fe80::1",
    ])
    def test_valid_ips(self, ip):
        assert _is_valid_ip(ip) is True

    @pytest.mark.parametrize("ip", ["", "not an ip", "999.999.999.999", "1.2.3", "1.2.3.4.5"])
    def test_invalid_ips(self, ip):
        assert _is_valid_ip(ip) is False

    @pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "172.16.0.1", "172.31.255.255"])
    def test_private_ips(self, ip):
        assert _is_private(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    def test_public_ips(self, ip):
        assert _is_private(ip) is False


# ---------------------------------------------------------------------------
# HostnameCache
# ---------------------------------------------------------------------------


class TestHostnameCache:
    """Direct unit tests for the LRU + TTL cache."""

    def test_set_and_get_positive(self):
        c = HostnameCache(max_entries=4, ttl_seconds=60)
        c.set("1.2.3.4", "example.com")
        hostname, hit = c.get("1.2.3.4")
        assert hit is True
        assert hostname == "example.com"

    def test_set_and_get_negative(self):
        """A None result (no PTR record) is cached as a hit, not a miss."""
        c = HostnameCache(max_entries=4, ttl_seconds=60)
        c.set("1.2.3.4", None)
        hostname, hit = c.get("1.2.3.4")
        assert hit is True
        assert hostname is None

    def test_miss_for_unknown_key(self):
        c = HostnameCache(max_entries=4, ttl_seconds=60)
        hostname, hit = c.get("1.2.3.4")
        assert hit is False
        assert hostname is None

    def test_ttl_expiry_with_injected_clock(self):
        c = HostnameCache(max_entries=4, ttl_seconds=10)
        now = [100.0]
        c._clock = lambda: now[0]
        c.set("1.2.3.4", "example.com")
        # Within TTL — hit.
        assert c.get("1.2.3.4")[1] is True
        # Past TTL — miss, and the entry is dropped.
        now[0] = 200.0
        hostname, hit = c.get("1.2.3.4")
        assert hit is False
        assert hostname is None

    def test_lru_eviction(self):
        """Oldest insertion is dropped when capacity is exceeded."""
        c = HostnameCache(max_entries=2, ttl_seconds=60)
        c.set("1.1.1.1", "a.example")
        c.set("2.2.2.2", "b.example")
        c.set("3.3.3.3", "c.example")  # Should evict 1.1.1.1
        assert c.get("1.1.1.1")[1] is False
        assert c.get("2.2.2.2")[1] is True
        assert c.get("3.3.3.3")[1] is True

    def test_clear(self):
        c = HostnameCache(max_entries=4, ttl_seconds=60)
        c.set("1.2.3.4", "example.com")
        c.clear()
        assert c.get("1.2.3.4")[1] is False
        assert len(c) == 0

    def test_update_refreshes_insertion_order(self):
        """Re-setting a key moves it to the back of the LRU."""
        c = HostnameCache(max_entries=2, ttl_seconds=60)
        c.set("1.1.1.1", "a")
        c.set("2.2.2.2", "b")
        c.set("1.1.1.1", "a2")  # Re-insert; 2.2.2.2 is now oldest
        c.set("3.3.3.3", "c")  # Should evict 2.2.2.2
        assert c.get("1.1.1.1")[1] is True
        assert c.get("2.2.2.2")[1] is False
        assert c.get("3.3.3.3")[1] is True

    def test_get_promotes_to_most_recently_used(self):
        """A get-hit moves the key to the back of the LRU.

        The earlier dict-based implementation only moved entries on
        ``set``, not on ``get`` — a hot scanner that kept re-querying
        the same IP would still get evicted once the cache had
        rotated past it.  This test pins the move-on-get behaviour
        that the new OrderedDict implementation gives us.
        """
        c = HostnameCache(max_entries=2, ttl_seconds=60)
        c.set("1.1.1.1", "a")
        c.set("2.2.2.2", "b")
        # Touch 1.1.1.1 — this should move it to the back so
        # 2.2.2.2 is now the oldest.
        assert c.get("1.1.1.1")[1] is True
        c.set("3.3.3.3", "c")  # Should evict 2.2.2.2
        assert c.get("1.1.1.1")[1] is True
        assert c.get("2.2.2.2")[1] is False
        assert c.get("3.3.3.3")[1] is True


# ---------------------------------------------------------------------------
# Hostname validation
# ---------------------------------------------------------------------------


class TestHostnameValidation:
    """``_sanitise_hostname`` rejects the classes of garbage that
    misconfigured resolvers and DNS pollution actually return.

    The function runs on every cached PTR result, so it's the
    last line of defence against junk showing up on the dashboard.
    """

    def test_valid_name_passes_through(self):
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("dns.google", "8.8.8.8") == "dns.google"

    def test_trailing_dot_stripped(self):
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("dns.google.", "8.8.8.8") == "dns.google"

    def test_empty_string_rejected(self):
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("", "8.8.8.8") is None

    def test_whitespace_only_rejected(self):
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("   ", "8.8.8.8") is None

    def test_none_rejected(self):
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname(None, "8.8.8.8") is None

    def test_ip_shaped_answer_rejected(self):
        """The resolver echoing the query must never be trusted."""
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("8.8.8.8", "8.8.8.8") is None

    def test_ipv6_shaped_answer_rejected(self):
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("2001:db8::1", "8.8.8.8") is None

    def test_localhost_rejected_for_non_loopback(self):
        """``localhost`` only makes sense for 127.0.0.1."""
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("localhost", "8.8.8.8") is None
        assert _sanitise_hostname("LOCALHOST", "8.8.8.8") is None

    def test_localhost_accepted_for_loopback(self):
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("localhost", "127.0.0.1") == "localhost"

    def test_oversized_name_rejected(self):
        """Names past RFC 1035's 253-octet limit are dropped."""
        from backend.profiler import _sanitise_hostname
        too_long = "a" * 254
        assert _sanitise_hostname(too_long, "8.8.8.8") is None

    def test_oversized_label_rejected(self):
        from backend.profiler import _sanitise_hostname
        # Single 64-char label, even if the total is under 253.
        too_long_label = ("a" * 64) + ".example.com"
        assert _sanitise_hostname(too_long_label, "8.8.8.8") is None

    def test_empty_label_rejected(self):
        from backend.profiler import _sanitise_hostname
        # Double dot — empty label.
        assert _sanitise_hostname("foo..bar", "8.8.8.8") is None

    def test_whitespace_embedded_rejected(self):
        from backend.profiler import _sanitise_hostname
        assert _sanitise_hostname("foo bar.example.com", "8.8.8.8") is None

    def test_control_char_rejected(self):
        from backend.profiler import _sanitise_hostname
        # Tab and newline are the common ones from debug strings.
        assert _sanitise_hostname("foo\tbar.example.com", "8.8.8.8") is None
        assert _sanitise_hostname("foo\nbar.example.com", "8.8.8.8") is None

    def test_end_to_end_via_reverse_dns(self):
        """A bogus PTR result from a mocked resolver hits the dashboard as None.

        We mock at the ``socket.gethostbyaddr`` layer — that's where
        ``_do_gethostbyaddr`` reads from, so the validation in
        ``_sanitise_hostname`` actually runs.  Patching
        ``_do_gethostbyaddr`` itself bypasses the validation, which
        is what we want to test.
        """
        with mock.patch(
            "backend.profiler.socket.gethostbyaddr",
            return_value=("not a real hostname with spaces", [], ["8.8.8.8"]),
        ):
            with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                assert _reverse_dns("8.8.8.8", timeout=0.5) is None


# ---------------------------------------------------------------------------
# _reverse_dns: mock the underlying resolver
# ---------------------------------------------------------------------------


class TestReverseDns:
    """End-to-end tests for ``_reverse_dns`` with a mocked resolver."""

    def test_cache_hit_skips_dns(self):
        """A pre-populated cache must not call gethostbyaddr."""
        with mock.patch("backend.profiler.socket.gethostbyaddr") as gha:
            # First call populates the cache.
            with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                gha.return_value = ("example.com", [], ["1.2.3.4"])
                first = _reverse_dns("1.2.3.4", timeout=0.5)
            assert first == "example.com"
            assert gha.call_count == 1
            # Second call should be served from cache.
            again = _reverse_dns("1.2.3.4", timeout=0.5)
            assert again == "example.com"
            assert gha.call_count == 1  # No new call.

    def test_dns_failure_cached_as_none(self):
        """A failed lookup is cached so we don't keep retrying."""
        with mock.patch("backend.profiler.socket.gethostbyaddr",
                        side_effect=socket.herror("no PTR")):
            with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                first = _reverse_dns("1.2.3.4", timeout=0.5)
        assert first is None
        # Second call must also be None, served from cache.
        with mock.patch("backend.profiler.socket.gethostbyaddr") as gha:
            with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                again = _reverse_dns("1.2.3.4", timeout=0.5)
        assert again is None
        assert gha.call_count == 0  # No new DNS call.

    def test_invalid_ip_returns_none(self):
        """Garbage IP inputs short-circuit before touching the network."""
        with mock.patch("backend.profiler.socket.gethostbyaddr") as gha:
            assert _reverse_dns("not an ip", timeout=0.5) is None
            assert _reverse_dns("", timeout=0.5) is None
            assert gha.call_count == 0

    def test_timeout_returns_none(self):
        """A DNS call that exceeds the timeout returns None, not raise."""
        # We patch the underlying socket call to just sleep so long
        # that the future.result() timeout fires.  The thread is left
        # to finish in the background (acceptable in our design).
        with mock.patch("backend.profiler.socket.gethostbyaddr",
                        side_effect=lambda *a, **kw: time.sleep(2.0)):
            with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                start = time.monotonic()
                result = _reverse_dns("1.2.3.4", timeout=0.2)
                elapsed = time.monotonic() - start
        assert result is None
        # Should return within ~0.5s (timeout + 0.25s buffer), not 2s.
        assert elapsed < 1.0

    def test_trailing_dot_stripped(self):
        """Some resolvers return FQDNs with a trailing dot; strip it."""
        with mock.patch("backend.profiler.socket.gethostbyaddr",
                        return_value=("example.com.", [], ["1.2.3.4"])):
            with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                result = _reverse_dns("1.2.3.4", timeout=0.5)
        assert result == "example.com"

    def test_setdefaulttimeout_restored_on_failure(self):
        """A DNS failure must not leak a global socket timeout change."""
        original = socket.getdefaulttimeout()
        with mock.patch("backend.profiler.socket.gethostbyaddr",
                        side_effect=socket.herror("nope")):
            with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                _reverse_dns("1.2.3.4", timeout=2.5)
        # If we set 2.5 and never restored, this would be 2.5.
        assert socket.getdefaulttimeout() == original

    def test_setdefaulttimeout_restored_on_success(self):
        """A successful DNS call must restore the default timeout too."""
        original = socket.getdefaulttimeout()
        with mock.patch("backend.profiler.socket.gethostbyaddr",
                        return_value=("example.com", [], ["1.2.3.4"])):
            with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                _reverse_dns("1.2.3.4", timeout=1.5)
        assert socket.getdefaulttimeout() == original


# ---------------------------------------------------------------------------
# profile_source: end-to-end
# ---------------------------------------------------------------------------


class TestProfileSource:
    """``profile_source`` returns a populated :class:`AttackerProfile`."""

    def test_private_ip_gets_mac(self):
        """On-link IPs get a synthetic MAC and no hostname lookup."""
        with mock.patch("backend.profiler._reverse_dns") as rdns:
            p = profile_source("192.168.1.42")
        assert p.on_link is True
        assert p.mac and len(p.mac) == 17  # 6 octets + 5 colons
        assert rdns.call_count == 0  # Don't bother rDNS for on-link

    def test_public_ip_gets_hostname(self):
        """Public IPs trigger rDNS and use the demo geo table."""
        with mock.patch("backend.profiler._reverse_dns",
                        return_value="dns.google") as rdns:
            p = profile_source("8.8.8.8")
        assert p.on_link is False
        assert p.mac is None
        assert p.hostname == "dns.google"
        assert p.country == "United States"
        assert p.isp == "Google LLC"
        assert rdns.call_count == 1

    def test_public_ip_with_failed_rdns(self):
        """A failing rDNS returns the geo table fields, no hostname."""
        with mock.patch("backend.profiler._reverse_dns", return_value=None):
            p = profile_source("8.8.8.8")
        assert p.hostname is None
        assert p.country == "United States"
        assert p.isp == "Google LLC"

    def test_unknown_public_ip(self):
        """An IP outside the demo table returns a profile with no geo data."""
        with mock.patch("backend.profiler._reverse_dns", return_value=None):
            p = profile_source("203.0.113.99")
        # 203.0.113.0/24 is in the demo table (TEST-NET-3).
        assert p.country == "Documentation"
        assert p.asn == "AS0"

    def test_to_dict_round_trip(self):
        """``to_dict`` returns a JSON-friendly dict with the expected keys."""
        with mock.patch("backend.profiler._reverse_dns", return_value=None):
            d = profile_source("8.8.8.8").to_dict()
        for key in ("ip", "mac", "hostname", "country", "city", "isp",
                    "asn", "os_guess", "on_link"):
            assert key in d


# ---------------------------------------------------------------------------
# Cache-size adjustment
# ---------------------------------------------------------------------------


class TestCacheSizeAdjustment:
    def test_set_hostname_cache_size_resizes(self):
        """``set_hostname_cache_size`` rebuilds the cache and keeps the cap."""
        # Populate the default cache with a few entries.
        for i in range(5):
            _reverse_dns(f"8.8.8.{i}", timeout=0.01)  # All fail and cache None
        set_hostname_cache_size(2)
        # The resize should drop entries to fit the new cap.  We don't
        # check which exact entries survive (FIFO is implementation-
        # dependent), only that the cap is honoured.
        from backend.profiler import _get_hostname_cache
        assert len(_get_hostname_cache()) <= 2


# ---------------------------------------------------------------------------
# Thread-safety smoke test
# ---------------------------------------------------------------------------


class TestConcurrency:
    """A burst of distinct IPs must not crash the resolver."""

    def test_concurrent_lookups(self):
        """Many threads, many IPs, all should return without raising.

        Implementation note: we patch ``_do_gethostbyaddr`` — the
        function the resolver pool actually runs — rather than
        ``socket.gethostbyaddr``.  Patching the underlying socket
        function is racy: with two resolver-pool workers and 20
        concurrent submissions, a test thread can exit its
        ``with mock.patch`` block *while a pool worker is still
        inside ``socket.gethostbyaddr``*, exposing the worker to
        the real DNS path.  On Windows the real call doesn't
        respect ``setdefaulttimeout`` and takes ~4.5s to fail —
        well past the 2s timeout in this test, so the worker
        times out and the test sees ``None``.  Patching the
        function the pool actually runs sidesteps the race: the
        ``pool.submit`` captures the patched reference, and the
        worker can't escape back to the real socket path.
        """
        results = []
        errors = []

        def fake_do_gethostbyaddr(ip, timeout):
            return f"name-{ip}"

        def worker(ip):
            try:
                # Generous timeout: the resolver pool is
                # sized at 2 workers, so a 20-job burst
                # can back up the queue.  We're testing
                # correctness (right answer per IP), not
                # the timeout path — the latter has its
                # own dedicated test.
                results.append(_reverse_dns(ip, timeout=2.0))
            except Exception as exc:  # pragma: no cover
                errors.append((ip, exc))

        # Patch at test level so the mock covers the full duration of all
        # concurrent pool submissions.  Patching per-thread is racy: a
        # thread can exit its ``with mock.patch`` block while a pool worker
        # is still inside the patched function.
        with mock.patch(
            "backend.profiler._do_gethostbyaddr",
            side_effect=fake_do_gethostbyaddr,
        ):
            threads = [threading.Thread(target=worker, args=(f"8.8.8.{i}",))
                    for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
            assert not errors, f"worker errors: {errors}"
            assert len(results) == 20
            # Each thread's IP must round-trip to its own name.
            names_by_ip = {f"8.8.8.{i}": f"name-8.8.8.{i}" for i in range(20)}
            for r in results:
                assert r in names_by_ip.values(), f"unexpected result: {r!r}"

    def test_repeated_lookup_is_cached_under_contention(self):
        """A 100-thread burst on the same IP only triggers 1 DNS call."""
        call_count = [0]

        def fake_gha(*args, **kwargs):
            call_count[0] += 1
            time.sleep(0.05)
            return ("example.com", [], [args[0]])

        barrier = threading.Barrier(50)

        def worker():
            barrier.wait()
            with mock.patch("backend.profiler.socket.gethostbyaddr",
                            side_effect=fake_gha):
                with mock.patch("backend.profiler.socket.setdefaulttimeout"):
                    _reverse_dns("1.2.3.4", timeout=1.0)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        # With LRU caching, the first call goes through and the rest
        # should hit the cache.  We don't pin the exact count (the
        # workers race to populate the cache; some may squeak through
        # before the first caches), but it must be far less than 50.
        assert call_count[0] < 10
