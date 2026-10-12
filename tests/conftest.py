import pytest

import config
from fakes import FakeNetwork
from sources import base


@pytest.fixture
def settings():
    """Fresh settings per test with no retry pause."""
    s = config.load_settings()
    s["retry"]["backoff_s"] = 0
    return s


@pytest.fixture
def net(monkeypatch):
    """Install a fake network: net(*outcomes, routes={...}) -> FakeNetwork."""
    def install(*outcomes, routes=None):
        fake = FakeNetwork(*outcomes, routes=routes)
        monkeypatch.setattr(base, "_send", fake)
        return fake
    monkeypatch.setattr(base, "_sleep", lambda s: None)
    return install
