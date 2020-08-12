# Standard Library
import os
from contextlib import contextmanager
from typing import Iterator

# 3rd-party
from monkeytype.config import DefaultConfig


class MonkeyConfig(DefaultConfig):
    @contextmanager
    def cli_context(self, command: str) -> Iterator[None]:
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "test_settings")
        import django

        django.setup()
        yield


CONFIG = MonkeyConfig()
