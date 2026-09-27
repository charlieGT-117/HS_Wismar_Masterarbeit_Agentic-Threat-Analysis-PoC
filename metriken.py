"""Erfasst je Analysedurchlauf den Tokenverbrauch (Input/Output), die aktive Modellzeit als Summe der API-Aufrufdauern sowie die gesamte Wall-Clock-Zeit und speichert diese in Output/lauf_metriken.json. 
Die aktive Modellzeit berücksichtigt keine nutzerbedingten Pausen an Human-in-the-Loop-Punkten. 
Fehler bei der Metrikerfassung beeinträchtigen den Analyseablauf nicht.

Verwendung:
    import metriken
    metriken.starte_lauf()                      # zu Beginn eines neuen Laufs
    ... (llm.py meldet jeden Aufruf via erfasse) ...
    with metriken.phase("Stufe 3 - Bedrohungen"):
        ...                                     # optionale Phasenmessung
    metriken.schreibe()                         # Output/lauf_metriken.json
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

_AUSGABE = Path(__file__).resolve().parent / "Output"

# Laufzustand (im Prozess gehalten; starte_lauf() setzt zurueck).
_zustand: dict = {}


def _leerer_zustand() -> dict:
    return {
        "lauf_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "start_wall": time.time(),
        "start_iso": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "je_modell": {},          # modell -> {aufrufe, input_tokens, output_tokens, modellzeit_s}
        "phasen": [],             # [{name, dauer_s, input_tokens, output_tokens, aufrufe}]
        "aufrufe": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "modellzeit_s": 0.0,      # Summe der API-Aufrufdauern (aktive Modellzeit)
    }


# Fortlaufende Stufengrenze (fuer stufe()): Zaehlerstand beim letzten Grenzpunkt.
_grenze: dict = {}


def starte_lauf() -> None:
    """Setzt alle Zaehler zurueck und markiert den Startzeitpunkt eines Laufs."""
    global _zustand, _grenze
    _zustand = _leerer_zustand()
    _grenze = {"input_tokens": 0, "output_tokens": 0, "aufrufe": 0, "modellzeit_s": 0.0}


def stufe(name: str) -> None:
    """Erfasst nach Abschluss jeder Analysestufe die Anzahl der Modellaufrufe, den Tokenverbrauch und die aktive Modellzeit, ohne nutzerbedingte Denk- und Prüfpausen zwischen den Stufen zu berücksichtigen."""
    global _grenze
    try:
        z = _sicher_zustand()
        if not _grenze:
            _grenze = {"input_tokens": 0, "output_tokens": 0, "aufrufe": 0, "modellzeit_s": 0.0}
        z["phasen"].append({
            "name": name,
            "aufrufe": z["aufrufe"] - _grenze["aufrufe"],
            "input_tokens": z["input_tokens"] - _grenze["input_tokens"],
            "output_tokens": z["output_tokens"] - _grenze["output_tokens"],
            "modellzeit_s": round(z["modellzeit_s"] - _grenze["modellzeit_s"], 1),
        })
        _grenze = {"input_tokens": z["input_tokens"], "output_tokens": z["output_tokens"],
                   "aufrufe": z["aufrufe"], "modellzeit_s": z["modellzeit_s"]}
        schreibe()
    except Exception:
        pass


def _sicher_zustand() -> dict:
    global _zustand
    if not _zustand:
        _zustand = _leerer_zustand()
    return _zustand


def erfasse(modell: str, input_tokens: int, output_tokens: int,
            dauer_s: float = 0.0) -> None:
    """Verbucht einen einzelnen Modellaufruf. Wird aus llm.py aufgerufen."""
    try:
        z = _sicher_zustand()
        eintrag = z["je_modell"].setdefault(
            modell, {"aufrufe": 0, "input_tokens": 0, "output_tokens": 0, "modellzeit_s": 0.0})
        eintrag["aufrufe"] += 1
        eintrag["input_tokens"] += int(input_tokens or 0)
        eintrag["output_tokens"] += int(output_tokens or 0)
        eintrag["modellzeit_s"] += float(dauer_s or 0.0)

        z["aufrufe"] += 1
        z["input_tokens"] += int(input_tokens or 0)
        z["output_tokens"] += int(output_tokens or 0)
        z["modellzeit_s"] += float(dauer_s or 0.0)
    except Exception:
        pass  # Messung darf den Lauf nie stoppen.


def tokens_aus_antwort(antwort) -> tuple[int, int]:
    """Liest (input_tokens, output_tokens) robust aus einer Anthropic- oder
    OpenAI-Antwort. Unbekanntes Format -> (0, 0)."""
    try:
        u = getattr(antwort, "usage", None)
        if u is None:
            return 0, 0
        # Anthropic: input_tokens / output_tokens (+ evtl. cache-Felder)
        it = getattr(u, "input_tokens", None)
        ot = getattr(u, "output_tokens", None)
        if it is not None or ot is not None:
            cache_read = getattr(u, "cache_read_input_tokens", 0) or 0
            cache_write = getattr(u, "cache_creation_input_tokens", 0) or 0
            return int((it or 0) + cache_read + cache_write), int(ot or 0)
        # OpenAI: prompt_tokens / completion_tokens
        pt = getattr(u, "prompt_tokens", 0) or 0
        ct = getattr(u, "completion_tokens", 0) or 0
        return int(pt), int(ct)
    except Exception:
        return 0, 0


class phase:
    """Kontextmanager fuer eine optionale Phasenmessung (z. B. je Analysestufe).

        with metriken.phase("Stufe 3 - Bedrohungen"):
            ...
    """

    def __init__(self, name: str):
        self.name = name

    def __enter__(self):
        z = _sicher_zustand()
        self._t0 = time.perf_counter()
        self._in0 = z["input_tokens"]
        self._out0 = z["output_tokens"]
        self._ruf0 = z["aufrufe"]
        return self

    def __exit__(self, *exc):
        z = _sicher_zustand()
        z["phasen"].append({
            "name": self.name,
            "dauer_s": round(time.perf_counter() - self._t0, 2),
            "input_tokens": z["input_tokens"] - self._in0,
            "output_tokens": z["output_tokens"] - self._out0,
            "aufrufe": z["aufrufe"] - self._ruf0,
        })
        schreibe()  # Zwischenstand sichern
        return False  # Ausnahmen nicht unterdruecken


def schnappschuss() -> dict:
    """Aktueller Stand als serialisierbares dict."""
    z = _sicher_zustand()
    jetzt = time.time()
    gesamt = z["input_tokens"] + z["output_tokens"]
    return {
        "lauf_id": z["lauf_id"],
        "start": z["start_iso"],
        "wall_clock_s": round(jetzt - z["start_wall"], 1),
        "aktive_modellzeit_s": round(z["modellzeit_s"], 1),
        "aufrufe": z["aufrufe"],
        "tokens": {
            "input": z["input_tokens"],
            "output": z["output_tokens"],
            "gesamt": gesamt,
        },
        "je_modell": {
            m: {
                "aufrufe": e["aufrufe"],
                "input_tokens": e["input_tokens"],
                "output_tokens": e["output_tokens"],
                "gesamt_tokens": e["input_tokens"] + e["output_tokens"],
                "modellzeit_s": round(e["modellzeit_s"], 1),
            } for m, e in z["je_modell"].items()
        },
        "phasen": z["phasen"],
    }


def schreibe(pfad: Path | None = None) -> Path:
    """Schreibt den aktuellen Stand nach Output/lauf_metriken.json."""
    ziel = pfad or (_AUSGABE / "lauf_metriken.json")
    try:
        ziel.parent.mkdir(exist_ok=True)
        ziel.write_text(json.dumps(schnappschuss(), ensure_ascii=False, indent=2),
                        encoding="utf-8")
    except Exception:
        pass
    return ziel
