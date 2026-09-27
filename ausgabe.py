"""Ausgabeverwaltung: Verwaltet zentral die erzeugten Artefakte des Prototyps im Verzeichnis Output, darunter Systemmodell, Analysemodell, Analysebericht und Prüfbericht. Die gespeicherten Ergebnisse dienen zugleich als Wissensbasis für die Beantwortung von Expertenfragen durch den CISO-Agenten. 
Konfigurations- und Eingabedateien werden getrennt verwaltet.
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
