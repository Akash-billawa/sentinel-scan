from unittest.mock import patch

from backend import arp


def test_parse_proc_net_arp():
    text = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0\n"
        "192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        "192.168.1.3      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
    )
    table = arp._parse_proc_net_arp(text)
    assert table["192.168.1.1"] == "00:11:22:33:44:55"
    assert table["192.168.1.3"] == "aa:bb:cc:dd:ee:ff"
    assert "192.168.1.2" not in table


def test_parse_arp_output():
    text = (
        "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on en0\n"
        "192.168.1.2          aa:bb:cc:dd:ee:66   ether   en0\n"
        "192.168.1.3          00:00:00:00:00:00   ether   en0\n"
    )
    table = arp._parse_arp_output(text)
    assert table["192.168.1.1"] == "00:11:22:33:44:55"
    assert table["192.168.1.2"] == "aa:bb:cc:dd:ee:66"
    assert "192.168.1.3" not in table


def test_get_mac_uses_cache():
    fake_table = {"10.0.0.1": "aa:bb:cc:dd:ee:ff"}
    with patch.object(arp, "get_table", return_value=fake_table):
        assert arp.get_mac("10.0.0.1") == "aa:bb:cc:dd:ee:ff"
        assert arp.get_mac("10.0.0.99") is None


def test_reset_cache():
    with patch.object(arp, "_cached_table", {"10.0.0.1": "aa:bb:cc:dd:ee:ff"}):
        arp.reset_cache()
        assert arp._cached_table == {}
