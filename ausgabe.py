"""Zentrale Stelle fuer die Ausgaben des Prototyps.

Alle erzeugten Artefakte (Systemmodell, Analysemodell, Bericht, Pruefbericht)
liegen im Ordner 'Output'. Dieser Ordner dient zugleich als Wissensbasis: Die
gespeicherte Analyse ist die Grundlage, auf die sich der CISO bei Expertenfragen
bezieht (siehe Wissensbasis.py).

Konfiguration (methodik.json, quellen.json, scoring.json) und Eingaben (Input/)
bleiben ausserhalb dieses Ordners.
"""

from pathlib import Path

PROJEKT = Path(__file__).resolve().parent

# Drei saubere Bereiche: Code (Hauptordner), Config und Output.
AUSGABE = PROJEKT / "Output"
AUSGABE.mkdir(exist_ok=True)

CONFIG = PROJEKT / "Config"
CONFIG.mkdir(exist_ok=True)


def pfad(name: str) -> Path:
    """Pfad einer Ausgabedatei im Output-Ordner."""
    return AUSGABE / name


def config_pfad(name: str) -> Path:
    """Pfad einer Konfigurationsdatei im Config-Ordner."""
    return CONFIG / name
