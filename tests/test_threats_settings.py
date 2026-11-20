import datetime as dt
import json

import pytest

from kaa import settings, threats
from kaa.config import Config

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Apple", "product": "iOS and iPadOS",
     "vulnerabilityName": "Apple WebKit flaw", "dateAdded": "2026-11-10",
     "shortDescription": "Remote code execution.", "requiredAction": "Apply updates.",
     "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-0002", "vendorProject": "Hikvision", "product": "Camera",
     "dateAdded": "2026-11-12", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2020-0003", "vendorProject": "Apple", "product": "macOS",
     "dateAdded": "2020-01-01"},
]}
TODAY = dt.date(2026, 11, 20)


def test_match_uses_vendors_of_your_devices_and_recent_entries_only():
    devices = [{"vendor": "Apple, Inc.", "hostname": "Alex's iPad Pro", "mac": "aa", "label": None},
               {"vendor": "Netatmo", "hostname": None, "mac": "bb", "label": None}]
    got = threats.match(KEV["vulnerabilities"], devices, today=TODAY)
    assert [g["cve"] for g in got] == ["CVE-2026-0001"]      # no Hikvision, nothing from 2020
    assert got[0]["devices"] == ["Alex's iPad Pro"]


def test_user_keywords_extend_the_watch():
    got = threats.match(KEV["vulnerabilities"], [], keywords=["hikvision"], today=TODAY)
    assert [g["cve"] for g in got] == ["CVE-2026-0002"] and got[0]["ransomware"]


def test_noise_words_do_not_create_matches():
    d = [{"vendor": "Silicon Laboratories", "mac": "cc"}]
    assert threats.match([{"vendorProject": "Silicon Labs", "dateAdded": "2026-11-01"}], d,
                         today=TODAY) == []


def test_load_ignores_garbage(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text("not json")
    assert threats.load(p) == []
    p.write_text(json.dumps(KEV))
    assert len(threats.load(p)) == 3


def test_settings_validate_and_persist_without_losing_other_keys(tmp_path):
    cfg = Config(home=tmp_path)
    (tmp_path / "config.toml").write_text('[server]\nport = 9000\n\n[scan]\nnetworks = ["10.0.0.0/24"]\n')
    settings.apply(cfg, {"notify": False, "wake_weekday": "06:45", "interval": 600,
                         "threat_keywords": ["EERO", " tp-link "]})
    settings.save(cfg, ["notify", "wake_weekday", "interval", "threat_keywords"])
    from kaa import config as config_mod
    again = config_mod.load(tmp_path)
    assert again.notify is False and again.wake_weekday == "06:45" and again.interval == 600
    assert again.threat_keywords == ["eero", "tp-link"]
    assert again.port == 9000 and again.networks == ["10.0.0.0/24"]


@pytest.mark.parametrize("bad", [{"interval": 5}, {"digest_hour": 30}, {"wake_weekend": "9h"},
                                 {"notify": "yes"}, {"host": "0.0.0.0"}])
def test_settings_refuse_bad_values(tmp_path, bad):
    with pytest.raises(settings.SettingsError):
        settings.apply(Config(home=tmp_path), bad)
