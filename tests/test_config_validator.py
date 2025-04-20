import pytest
import tempfile
import os
from framework.config_validator import ConfigValidator

VALID_CONFIG = """
[General]
ScanMemoryLimit=1024
PackageType=RPM
ExecArgMax=10
AdditionalDNSLookup=Yes
CoreDumps=False
RevealSensitiveInfoInTraces=No
ExecEnvMax=50
MaxInotifyWatches=10000
CoreDumpsPath=.
UseFanotify=true
KsvlaMode=no
MachineId=7b5cc0e7-0205-48e1-bf63-347531eef193
StartupTraces=yes
MaxInotifyInstances=1024
Locale=en-US.UTF-8

[Watchdog]
ConnectTimeout=1m
MaxVirtualMemory=auto
MaxMemory=100
PingInterval=100
"""

@pytest.fixture
def valid_config_file(tmp_path, monkeypatch):
    file = tmp_path / "config.ini"
    file.write_text(VALID_CONFIG)
    monkeypatch.setenv("CONFIG_PATH", str(file))
    return file


def test_valid_config(valid_config_file):
    validator = ConfigValidator()
    assert validator.load()
    errors = validator.validate()
    assert not errors
