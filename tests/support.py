"""Temporary host/profile fixtures; never use real user state."""
from copy import deepcopy
from pathlib import Path
import tempfile

import yaml


class ProfileFixture:
    def __enter__(self):
        from t3_sandbox.paths import HostContext
        self.temp = tempfile.TemporaryDirectory(prefix="t3-profile-test-")
        self.root = Path(self.temp.name)
        self.host = HostContext(self.root / "host", 1234, 2345, "testuser")
        self.host.home.mkdir()
        self.profile_dir = self.root / "profiles"
        return self

    def __exit__(self, *args):
        self.temp.cleanup()

    def write(self, name, overrides):
        def merge(base, updates):
            for key, value in updates.items():
                if isinstance(value, dict) and isinstance(base.get(key), dict):
                    merge(base[key], value)
                else:
                    base[key] = deepcopy(value)
            return base
        path = self.profile_dir / f"{name}.yaml"
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        base = yaml.safe_load(path.read_text()) if path.exists() else {"version": 1}
        path.write_text(yaml.safe_dump(merge(base, overrides), sort_keys=False))
        return path

    def load(self, name, overrides=None):
        from t3_sandbox.profiles import load_profile
        if overrides is not None:
            self.write(name, overrides)
        return load_profile(name, self.profile_dir, self.host)
