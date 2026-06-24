from backend.oui import lookup, normalize


def test_normalize_canonical_form():
    assert normalize("AA:BB:CC:DD:EE:FF") == "AABBCC"


def test_normalize_dash_form():
    assert normalize("AA-BB-CC-DD-EE-FF") == "AABBCC"


def test_normalize_no_separators():
    assert normalize("aabbccddeeff") == "AABBCC"


def test_normalize_empty_returns_empty():
    assert normalize("") == ""
    assert normalize("xx") == ""


def test_lookup_apple():
    assert lookup("A4:83:E7:11:22:33") == "Apple, Inc."


def test_lookup_unknown_returns_none():
    assert lookup("FF:FF:FF:11:22:33") is None


def test_lookup_raspberry_pi():
    assert lookup("B8:27:EB:AA:BB:CC") == "Raspberry Pi Foundation"
