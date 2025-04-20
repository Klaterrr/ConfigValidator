import pytest
import os
from framework.config_validator import ConfigValidator

VALID_CONFIG_TEMPLATE = """
[General]
ScanMemoryLimit=1024
PackageType=RPM
ExecArgMax=10
AdditionalDNSLookup=Yes
CoreDumps=False
RevealSensitiveInfoInTraces=No
ExecEnvMax=50
MaxInotifyWatches=10000
CoreDumpsPath={core_path}
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
    # Создаем существующую папку для CoreDumpsPath
    core_dir = tmp_path / "dumps"
    core_dir.mkdir()
    config_file = tmp_path / "config.ini"
    config_file.write_text(VALID_CONFIG_TEMPLATE.format(core_path=core_dir))
    monkeypatch.setenv("CONFIG_PATH", str(config_file))
    return config_file


def test_valid_config(valid_config_file):
    validator = ConfigValidator()
    assert validator.load()
    errors = validator.validate()
    assert not errors
