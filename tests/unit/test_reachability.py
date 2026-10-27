import glob
from backend.structural.reachability import analyze_bytes, analyze_path


def _verdict(path, cap="javascript"):
    r = analyze_path(path)
    for c in r.capabilities:
        if c["capability"] == cap:
            return c
    return None


def test_dormant_js_not_reachable():
    c = _verdict("tests/fixtures/crafted/fixture_dormant.pdf")
    assert c is not None and c["verdict"] == "PRESENT_DORMANT"
    assert c["reachable_from_trigger"] is False
    assert c["naive_count"] >= 1          # a byte counter DOES see it


def test_active_onopen_reachable():
    c = _verdict("tests/fixtures/crafted/fixture_active_onopen.pdf")
    assert c["verdict"] == "ACTIVE_ONOPEN"
    assert c["trigger_class"] == "auto"
    assert c["min_hops"] is not None


def test_buried_js_evades_byte_count_but_not_reachability():
    """The headline robustness claim: naive byte count = 0, yet ACTIVE."""
    c = _verdict("tests/fixtures/crafted/fixture_active_buried.pdf")
    assert c["verdict"] == "ACTIVE_ONOPEN"
    assert c["naive_count"] == 0


def test_interaction_only_downgraded():
    c = _verdict("tests/fixtures/crafted/fixture_interaction_only.pdf")
    assert c["verdict"] == "ACTIVE_ONINTERACT"
    assert c["trigger_class"] == "interaction"


def test_empty_and_garbage_safe():
    assert analyze_bytes(b"").error is not None
    r = analyze_bytes(b"this is not a pdf at all" * 10)
    assert r.parsed is False            # handled, no crash


def test_non_pdf_with_pdf_bytes_header():
    r = analyze_bytes(b"%PDF-1.7\n garbage body no xref")
    assert r.error is not None or r.parsed is False


def test_all_real_pdfs_no_crash():
    for p in glob.glob("tests/fixtures/real_pdfs/*.pdf"):
        r = analyze_path(p)
        assert r.sha256 and isinstance(r.capabilities, list)
