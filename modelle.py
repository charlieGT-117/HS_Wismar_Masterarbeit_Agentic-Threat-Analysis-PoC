"""Zentrale Rolle-zu-Modell-Zuordnung.

Liest Config/modelle.json und liefert je Rolle Anbieter und Modell. So ist die Zuordnung zentral implementiert.
"""

import json
from pathlib import Path

CONFIG = Path(__file__).resolve().parent / "Config"
_cache = None


def _laden() -> dict:
    global _cache
    if _cache is None:
        _cache = json.loads((CONFIG / "modelle.json").read_text(encoding="utf-8"))
    return _cache


def _eintrag(rolle: str) -> dict:
    rollen = _laden().get("rollen", {})
    return rollen.get(rolle) or rollen.get("ciso", {"anbieter": "anthropic",
                                                    "modell": "claude-sonnet-4-6"})


def modell_fuer(rolle: str) -> str:
    return _eintrag(rolle)["modell"]


def anbieter_fuer(rolle: str) -> str:
    return _eintrag(rolle).get("anbieter", "anthropic")


def alle_zuordnungen() -> dict:
    """Die komplette Rolle-zu-Modell-Zuordnung."""
    return _laden().get("rollen", {})
