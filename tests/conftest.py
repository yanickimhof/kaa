import pytest

from kaa import config as config_mod
from kaa.db import Database
from kaa.service import Service


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("KAA_HOME", str(tmp_path))
    cfg = config_mod.load()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(cfg.db_path)
    return cfg, db, Service(cfg, db)
