import pytest

from kaa.identify import engine, llm
from kaa.service import builtin_signatures

RULES = engine.load_rules(builtin_signatures())


def facts(**kw):
    base = {"vendor": None, "hostname": None, "randomized_mac": False, "is_gateway": False,
            "mdns_services": [], "mdns_names": [], "ssdp_server": "", "ssdp_st": [],
            "open_ports": []}
    base.update(kw)
    return base


def test_builtin_signatures_valid_and_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids)) and len(ids) > 30


def test_sonos_is_speaker_with_evidence():
    cls, conf, ev = engine.classify(
        facts(vendor="Sonos, Inc.", mdns_services=["_sonos._tcp"]), RULES)
    assert cls == "speaker" and conf > 0.95
    assert {e["rule"] for e in ev} == {"vendor-sonos", "mdns-sonos"}


def test_gateway_is_router():
    cls, conf, _ = engine.classify(facts(is_gateway=True), RULES)
    assert cls == "router" and conf >= 0.9


def test_hostname_alone_is_weaker_than_agreement():
    alone, c1, _ = engine.classify(facts(hostname="Yanicks-iPhone"), RULES)
    assert alone == "phone" and c1 == pytest.approx(0.8)


def test_nothing_known_is_unknown():
    assert engine.classify(facts(), RULES) == ("unknown", 0.0, [])


def test_printer_by_port_and_service():
    cls, _, ev = engine.classify(
        facts(open_ports=[80, 9100], mdns_services=["_ipp._tcp"]), RULES)
    assert cls == "printer" and len(ev) >= 2


def test_confidence_never_exceeds_cap():
    _, conf, _ = engine.classify(
        facts(vendor="Sonos", mdns_services=["_sonos._tcp"], hostname="sonos-living"), RULES)
    assert conf <= engine.MAX_CONF


def test_bad_signature_class_rejected(tmp_path):
    (tmp_path / "x.yaml").write_text(
        "- {id: x, class: toaster, confidence: 0.5, when: {vendor: {contains: a}}}\n")
    with pytest.raises(ValueError):
        engine.load_rules(tmp_path)


# ---- AI guard rails -----------------------------------------------------

def test_ai_answer_must_use_closed_class_list():
    assert llm.parse_answer('{"class": "toaster", "confidence": 0.9}') is None
    assert llm.parse_answer("no json here") is None
    assert llm.parse_answer('{"class": "unknown", "confidence": 0.9}') is None


def test_ai_confidence_is_capped():
    cls, conf, _ = llm.parse_answer('```json\n{"class":"camera","confidence":0.99}\n```')
    assert cls == "camera" and conf == llm.AI_CONF_CAP


def test_ai_endpoint_must_be_loopback():
    llm.check_endpoint("http://127.0.0.1:8080/v1", False)
    llm.check_endpoint("http://localhost:8080/v1", False)
    with pytest.raises(llm.AIConfigError):
        llm.check_endpoint("https://api.example.com/v1", False)
    llm.check_endpoint("https://api.example.com/v1", True)


def test_ai_payload_never_contains_identifiers():
    p = llm.payload_for({"vendor": "X", "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.2",
                         "hostname": "h", "open_ports": []})
    assert set(p) == {"vendor", "hostname"}
