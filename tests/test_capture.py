"""Tests for capture interface resolution.

Verifies resolving human-readable names, descriptions, network names, and
IP addresses to Scapy interface objects.
"""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from backend import capture


class MockIface:
    def __init__(self, name: str, description: str, network_name: str, guid: str, ip: str) -> None:
        self.name = name
        self.description = description
        self.network_name = network_name
        self.guid = guid
        self.ip = ip


def test_resolve_scapy_interface(monkeypatch) -> None:
    # Setup mock interfaces
    mock_ifaces = {
        "{guid-wifi}": MockIface("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz", "\\Device\\NPF_{guid-wifi}", "{guid-wifi}", "192.168.1.100"),
        "{guid-eth}": MockIface("Ethernet 3", "Remote NDIS based Internet Sharing Device #2", "\\Device\\NPF_{guid-eth}", "{guid-eth}", "172.31.247.84"),
        "\\Device\\NPF_Loopback": MockIface("\\Device\\NPF_Loopback", "Software Loopback Interface 1", "\\Device\\NPF_Loopback", "\\Device\\NPF_Loopback", "127.0.0.1"),
    }
    
    mock_conf = MagicMock()
    mock_conf.ifaces = mock_ifaces
    
    # Mock scapy.all.conf inside capture
    import scapy.all
    monkeypatch.setattr(scapy.all, "conf", mock_conf)
    
    # Test matching by exact IP
    res = capture.resolve_scapy_interface("172.31.247.84")
    assert res is not None
    assert res.name == "Ethernet 3"
    
    # Test matching by exact Name
    res = capture.resolve_scapy_interface("Wi-Fi")
    assert res is not None
    assert res.name == "Wi-Fi"
    
    # Test matching by description substring (case-insensitive)
    res = capture.resolve_scapy_interface("Intel(R) Wi-Fi")
    assert res is not None
    assert res.name == "Wi-Fi"
    
    # Test matching by network name
    res = capture.resolve_scapy_interface("\\Device\\NPF_{guid-eth}")
    assert res is not None
    assert res.name == "Ethernet 3"

    # Test non-matching
    res = capture.resolve_scapy_interface("NonExistent")
    assert res is None


def test_live_capture_auto_detect(monkeypatch) -> None:
    from backend.capture import LiveCapture
    from backend.detector import DetectionEngine
    from backend.config import Settings
    
    mock_ifaces = {
        "{guid-wifi}": MockIface("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz", "\\Device\\NPF_{guid-wifi}", "{guid-wifi}", "192.168.1.100"),
        "{guid-eth}": MockIface("Ethernet 3", "Remote NDIS based Internet Sharing Device #2", "\\Device\\NPF_{guid-eth}", "{guid-eth}", "172.31.247.84"),
        "{guid-miniport}": MockIface("WAN Miniport (Network Monitor)", "WAN Miniport (Network Monitor)", "\\Device\\NPF_{guid-miniport}", "{guid-miniport}", "10.0.0.1"),
        "{guid-linklocal}": MockIface("Local Area Connection* 2", "Microsoft Wi-Fi Direct Virtual Adapter #2", "\\Device\\NPF_{guid-linklocal}", "{guid-linklocal}", "169.254.68.50"),
        "\\Device\\NPF_Loopback": MockIface("\\Device\\NPF_Loopback", "Software Loopback Interface 1", "\\Device\\NPF_Loopback", "\\Device\\NPF_Loopback", "127.0.0.1"),
    }
    
    mock_conf = MagicMock()
    mock_conf.ifaces = mock_ifaces
    mock_conf.use_pcap = True
    
    import scapy.all
    monkeypatch.setattr(scapy.all, "conf", mock_conf)
    
    # Mock AsyncSniffer
    mock_sniffer_class = MagicMock()
    mock_sniffer_inst = MagicMock()
    mock_sniffer_inst.thread.is_alive.return_value = True
    mock_sniffer_class.return_value = mock_sniffer_inst
    monkeypatch.setattr(scapy.all, "AsyncSniffer", mock_sniffer_class)
    
    engine = MagicMock(spec=DetectionEngine)
    settings = Settings(interface="", capture_mode="live")
    
    capture_obj = LiveCapture(engine, settings)
    success = capture_obj.start()
    
    assert success is True
    assert mock_sniffer_class.call_count == 2
    
    called_ifaces = [call.kwargs.get("iface") for call in mock_sniffer_class.call_args_list]
    assert mock_ifaces["{guid-wifi}"] in called_ifaces
    assert mock_ifaces["{guid-eth}"] in called_ifaces

