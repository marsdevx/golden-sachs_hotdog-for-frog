"""Explicit registration: policy selects names, never executable module paths."""
from collections.abc import Callable

import httpx

from firewall_app.providers.base import Connection, ModelProvider

ProviderFactory = Callable[[Connection, httpx.AsyncClient], ModelProvider]


class ProviderRegistry:
    def __init__(self) -> None:
        self._factories: dict[str, ProviderFactory] = {}

    def register(self, name: str, factory: ProviderFactory) -> None:
        if not name or name in self._factories:
            raise ValueError(f"duplicate or empty provider name: {name!r}")
        self._factories[name] = factory

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._factories))

    def create(self, name: str, connection: Connection, client: httpx.AsyncClient) -> ModelProvider:
        if name not in self._factories:
            raise LookupError(f"unknown provider {name!r}")
        return self._factories[name](connection, client)
