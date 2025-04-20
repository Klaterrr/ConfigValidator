import os
import configparser
import uuid
import re

class ConfigValidator:
    def __init__(self, path=None):
        self.path = path or os.environ.get('CONFIG_PATH', '/var/opt/kaspersky/config.ini')
        self.parser = configparser.ConfigParser()
        self.errors = []

    def load(self):
        if not os.path.isfile(self.path):
            self.errors.append(f"Config file not found: {self.path}")
            return False
        self.parser.read(self.path)
        return True

    def validate(self):
        self.validate_general()
        self.validate_watchdog()
        return self.errors

    def validate_general(self):
        section = 'General'
        if section not in self.parser:
            self.errors.append(f"Missing [{section}] section")
            return
        g = self.parser[section]
        self._validate_int_range(g, 'ScanMemoryLimit', 1024, 8192)
        self._validate_enum(g, 'PackageType', ['rpm','deb'])
        self._validate_int_range(g, 'ExecArgMax', 10, 100)
        self._validate_bool(g, 'AdditionalDNSLookup')
        self._validate_bool(g, 'CoreDumps')
        self._validate_bool(g, 'RevealSensitiveInfoInTraces')
        self._validate_int_range(g, 'ExecEnvMax', 10, 100)
        self._validate_int_range(g, 'MaxInotifyWatches', 1000, 1000000)
        self._validate_path(g, 'CoreDumpsPath')
        self._validate_bool(g, 'UseFanotify')
        self._validate_bool(g, 'KsvlaMode')
        self._validate_uuid(g, 'MachineId')
        self._validate_bool(g, 'StartupTraces')
        self._validate_int_range(g, 'MaxInotifyInstances', 1024, 8192)
        self._validate_locale(g, 'Locale')

    def validate_watchdog(self):
        section = 'Watchdog'
        if section not in self.parser:
            self.errors.append(f"Missing [{section}] section")
            return
        w = self.parser[section]
        self._validate_timeout(w, 'ConnectTimeout', 'm', 1, 120)
        self._validate_enum(w, 'MaxVirtualMemory', ['off','auto'], float_range=(0, 100))
        self._validate_enum(w, 'MaxMemory', ['off','auto'], float_range=(0, 100))
        self._validate_int_range(w, 'PingInterval', 100, 10000)

    def _validate_int_range(self, section, key, min_val, max_val):
        if key not in section:
            self.errors.append(f"Missing key {key}")
            return
        try:
            v = int(section[key])
            if not (min_val <= v <= max_val):
                raise ValueError
        except Exception:
            self.errors.append(f"{key} must be integer in [{min_val}, {max_val}]")

    def _validate_enum(self, section, key, choices, float_range=None):
        if key not in section:
            self.errors.append(f"Missing key {key}")
            return
        val = section[key].strip()
        lower = val.lower()
        if lower in choices:
            return
        if float_range:
            try:
                f = float(val)
                low, high = float_range
                if not (low < f <= high):
                    raise ValueError
                return
            except Exception:
                pass
        self.errors.append(f"{key} must be one of {choices} or float in {float_range}")

    def _validate_bool(self, section, key):
        if key not in section:
            self.errors.append(f"Missing key {key}")
            return
        if section[key].strip().lower() not in ['true','false','yes','no']:
            self.errors.append(f"{key} must be boolean (true/false/yes/no)")

    def _validate_path(self, section, key):
        if key not in section:
            self.errors.append(f"Missing key {key}")
            return
        path = section[key].strip()
        if not os.path.isabs(path) or not os.path.isdir(path):
            self.errors.append(f"{key} must be an existing absolute directory path")

    def _validate_uuid(self, section, key):
        if key not in section:
            self.errors.append(f"Missing key {key}")
            return
        try:
            uuid.UUID(section[key].strip())
        except Exception:
            self.errors.append(f"{key} must be a valid UUID")

    def _validate_timeout(self, section, key, suffix, min_val, max_val):
        if key not in section:
            self.errors.append(f"Missing key {key}")
            return
        val = section[key].strip()
        if not val.endswith(suffix):
            self.errors.append(f"{key} must end with '{suffix}' suffix")
            return
        num = val[:-len(suffix)]
        try:
            n = int(num)
            if not (min_val <= n <= max_val):
                raise ValueError
        except Exception:
            self.errors.append(f"{key} must be integer in [{min_val}-{max_val}] with suffix '{suffix}'")

    def _validate_locale(self, section, key):
        if key not in section:
            self.errors.append(f"Missing key {key}")
            return
        pattern = re.compile(r'^[a-zA-Z]{2,3}([-_][a-zA-Z]{2,3})(\.[\w\-]+)?$')
        if not pattern.match(section[key].strip()):
            self.errors.append(f"{key} must follow RFC 3066 format, e.g. en-US.UTF-8")