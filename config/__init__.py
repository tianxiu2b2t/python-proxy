import os
from pathlib import Path
from typing import Any
import dotenv
import yaml

ROOT = Path(__file__).parent.parent

class Env:
    def __init__(self):
        if not dotenv.load_dotenv(dotenv.find_dotenv()):
            raise Exception("No .env file found")
        if self.contains("ENV"):
            if not dotenv.load_dotenv(f".env.{self.type}"):
                raise Exception(f"No .env.{self.type} file found")
        
    def get(self, key: str, default=None):
        return os.getenv(key, default)
    
    def contains(self, key: str):
        return self.get(key) is not None
    
    def get_int(self, key: str, default=None):
        value = self.get(key, default)
        if value is None:
            return None
        return int(value)

    def get_float(self, key: str, default=None):
        value = self.get(key, default)
        if value is None:
            return None
        return float(value)
    
    def get_bool(self, key: str, default=None):
        value = self.get(key, default)
        if value is None:
            return None
        return value.lower() in ['true', '1', 'yes']
        

    def __contains__(self, key: str) -> bool:
        return self.contains(key)
    
    def __getitem__(self, key: str):
        return self.get(key)


    @property
    def type(self):
        return self.get('ENV') or "default"
    
    @property
    def dev(self):
        return self.type.lower() == "dev"

defaults = {}

class CFG:
    def __init__(self, path: str) -> None:
        self.file = Path(path)
        self.cfg = {}
        if self.file.exists():
            self.load()
        else:
            for key, value in defaults.items():
                self.set(key, value)

    def load(self):
        with open(self.file, "r", encoding="utf-8") as f:
            self.cfg = yaml.load(f.read(), Loader=yaml.FullLoader) or {}

    def get(self, key: str, def_: Any = None) -> Any:
        value = os.environ.get(key, None) or self._get_value(self.cfg, key.split("."))
        if value is None and def_ is None:
            print(f"[Config] {key} is not set, does it exist?")
            if key in defaults:
                value = defaults.get(key, None)
                if value is not None:
                    self.set(key, value)
        return value

    def set(self, key: str, value: Any):
        self._set_value(self.cfg, key.split("."), value)
        self.save()

    def save(self):
        self.file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as f:
            yaml.dump(data=self.cfg, stream=f, allow_unicode=True)

    def _get_value(self, dict_obj, keys):
        for key in keys:
            if key in dict_obj:
                dict_obj = dict_obj[key]
            else:
                return None
        return dict_obj

    def _set_value(self, dict_obj, keys, value):
        for _, key in enumerate(keys[:-1]):
            if key not in dict_obj:
                dict_obj[key] = {}
            dict_obj = dict_obj[key]
        dict_obj[keys[-1]] = value

    
env = Env()
config = CFG(f"{ROOT}/config.yml")
__all__ = ['env', 'config']
