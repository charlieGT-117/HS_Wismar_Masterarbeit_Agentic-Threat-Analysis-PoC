"""Stufe 4: Bewertung und Priorisierung (CISO als Risikoanalyst, FA-18 / FA-19).

Bewertet jede Bedrohung nach dem offengelegten Schema (scoring.json):
Eintrittswahrscheinlichkeit x Auswirkung. Die Auswirkung bemisst sich an der
Kritikalitaet der erreichbaren Assets, die Eintrittswahrscheinlichkeit an
Erreichbarkeit, Vorbedingungen und dem Ausnutzungsstatus aus den TI-Befunden (FA-18).

Der CISO liefert Wahrscheinlichkeit, Auswirkung, Asset-Bezug und Begruendungen;
Score und Prioritaetsklasse werden im Code aus dem Schema berechnet (reproduzierbar).
"""

import json
import re
from pathlib import Path

from llm import frage_modell, repariere_json
from ausgabe import AUSGABE, CONFIG
from modelle import modell_fuer

MODELL = modell_fuer("ciso")
MAX_TOKENS = 12000
STAPEL = 12          # so viele Bedrohungen je Aufruf (gegen Token-Limit, LL-1)
ORDNER = Path(__file__).resolve().parent


def _json_aus_text(text: str) -> dict:
    return repariere_json(text, MODELL)


def lade_analysemodell() -> dict:
    pfad = AUSGABE / "analysemodell.json"
    if not pfad.exists():
        raise FileNotFoundError("Kein analysemodell.json - bitte zuerst Stufe 3 laufen lassen.")
    return json.loads(pfad.read_text(encoding="utf-8"))


def lade_scoring() -> dict:
    return json.loads((CONFIG / "scoring.json").read_text(encoding="utf-8"))


def _prioritaet(score: int, scoring: dict) -> str:
    for klasse in scoring.get("prioritaetsklassen", []):
        if score >= klasse["min_score"]:
            return klasse["name"]
    return "niedrig"


def _auftrag(scoring: dict) -> str:
    dim = scoring["dimensionen"]
    ew = "\n".join(f"    {k}: {v}" for k, v in dim["eintrittswahrscheinlichkeit"].items())
    aw = "\n".join(f"    {k}: {v}" for k, v in dim["auswirkung"].items())
    return f"""Du bist der CISO-Agent in der Rolle des Risikoanalysten. Bewerte die unten
gelisteten Bedrohungen nach diesem offengelegten Schema.

EINTRITTSWAHRSCHEINLICHKEIT (1-5):
{ew}
AUSWIRKUNG (1-5), gemessen an der Kritikalitaet der erreichbaren Assets:
{aw}

Regeln:
- Beziehe den Ausnutzungsstatus aus den TI-Befunden ein (aktiv ausgenutzt -> hohe
  Wahrscheinlichkeit).
- Verweise fuer die Auswirkung auf mindestens ein Asset (asset_refs), sofern vorhanden.
- Halte die Begruendungen knapp (je ein Satz).

Antworte ausschliesslich als JSON-Objekt:
{{"bewertungen": [
  {{"threat_ref": "T-..", "eintrittswahrscheinlichkeit": 1-5, "auswirkung": 1-5,
    "asset_refs": ["A-.."], "ew_begruendung": "...", "auswirkung_begruendung": "..."}}
]}}
"""


def bewerte(modell: dict, scoring: dict) -> list:
    threats = modell.get("bedrohungen", [])
    assets = modell.get("assets", [])
    ti = modell.get("ti_befunde", modell.get("ti_artifacts", []))
    auftrag = _auftrag(scoring)
    bewertungen = []

    for i in range(0, len(threats), STAPEL):
        stapel = threats[i:i + STAPEL]
        print(f"\n[CISO] Bewerte Bedrohungen {i + 1}-{i + len(stapel)} von {len(threats)} ...")
        kontext = {
            "bedrohungen": [{"id": t["id"], "titel": t["titel"], "stride": t["stride"],
                             "element_ref": t["element_ref"], "surface_ref": t["surface_ref"],
                             "ti_refs": t.get("ti_refs", [])} for t in stapel],
            "assets": assets,
            "ti_befunde": [{"id": a["id"], "identifier": a.get("identifier"),
                            "exploitation_status": a.get("exploitation_status")} for a in ti],
        }
        try:
            ergebnis = _json_aus_text(frage_modell(
                auftrag + "\n\nZU BEWERTEN:\n" + json.dumps(kontext, ensure_ascii=False, indent=2),
                modell=MODELL, max_tokens=MAX_TOKENS))
        except Exception as exc:
            print(f"   Stapel uebersprungen ({type(exc).__name__}).")
            continue

        for b in ergebnis.get("bewertungen", []):
            ew = int(b.get("eintrittswahrscheinlichkeit", 1))
            aw = int(b.get("auswirkung", 1))
            score = ew * aw
            bewertungen.append({
                "threat_ref": b.get("threat_ref", ""),
                "eintrittswahrscheinlichkeit": ew,
                "auswirkung": aw,
                "score": score,
                "prioritaet": _prioritaet(score, scoring),
                "asset_refs": b.get("asset_refs", []) or [],
                "ew_begruendung": b.get("ew_begruendung", ""),
                "auswirkung_begruendung": b.get("auswirkung_begruendung", ""),
                "schema": scoring.get("id", ""),
            })

    return bewertungen


def priorisierte_liste(modell: dict) -> list:
    """Bedrohungen nach Score absteigend, angereichert mit Titel/Kategorie."""
    nach_id = {t["id"]: t for t in modell.get("bedrohungen", [])}
    reihen = []
    for b in modell.get("bewertungen", []):
        if b.get("threat_ref") not in nach_id:
            continue   # verworfene/entfernte Bedrohungen nicht mehr listen
        t = nach_id.get(b["threat_ref"], {})
        reihen.append({
            "id": b["threat_ref"], "titel": t.get("titel", ""), "stride": t.get("stride", ""),
            "prioritaet": b["prioritaet"], "score": b["score"],
            "ew": b["eintrittswahrscheinlichkeit"], "auswirkung": b["auswirkung"],
            "surface_ref": t.get("surface_ref", ""), "asset_refs": b.get("asset_refs", []),
        })
    reihen.sort(key=lambda r: r["score"], reverse=True)
    return reihen


if __name__ == "__main__":
    modell = lade_analysemodell()
    scoring = lade_scoring()
    modell["bewertungen"] = bewerte(modell, scoring)
    modell["scoring_schema"] = scoring

    (AUSGABE / "analysemodell.json").write_text(
        json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")

    liste = priorisierte_liste(modell)
    von_prio = {}
    for r in liste:
        von_prio[r["prioritaet"]] = von_prio.get(r["prioritaet"], 0) + 1

    print(f"\n[CISO] {len(liste)} Bedrohungen bewertet. Prioritaetsverteilung: {dict(von_prio)}")
    print("\nPriorisierte Bedrohungsliste (Top 10):")
    for r in liste[:10]:
        print(f"  [{r['prioritaet']:>8}] {r['id']} {r['titel']}  (Score {r['score']}, {r['stride']})")
    print("\nGespeichert in analysemodell.json.")
