"""Stufe 2: Angriffsflaechen ableiten (CISO, KF-2 / FA-05 / FA-06).

Nimmt das FREIGEGEBENE Systemmodell aus Stufe 1 und leitet daraus die
Angriffsflaechen ab. Jede Angriffsflaeche verweist auf mindestens ein
Modellelement und auf die darueber erreichbaren Assets (FA-06) - das ist der
Weg, ueber den Asset-Kritikalitaet spaeter in die Priorisierung gelangt.

Das Ergebnis wird an das gemeinsame Analysemodell angehaengt (analysemodell.json),
das ueber die Prozessschritte hinweg waechst.
"""

import json
import re
from pathlib import Path

from llm import frage_modell, repariere_json
from ausgabe import AUSGABE
from modelle import modell_fuer

MODELL = modell_fuer("ciso")
MAX_TOKENS = 16000

ORDNER = Path(__file__).resolve().parent


AUFTRAG = """Du bist der CISO-Agent. Dir liegt ein freigegebenes Systemmodell vor
(Elemente, Datenfluesse, Vertrauensgrenzen, Assets). Leite daraus die ANGRIFFSFLAECHEN ab.

Regeln:
- Jede Grenzueberschreitung (Datenfluss mit "ueberschreitet_grenze": true) ist eine
  Angriffsflaeche.
- Jedes extern erreichbare Element (externe Entitaet, oeffentlich erreichbarer Dienst,
  Eingang von aussen) ist eine Angriffsflaeche.
- Vergib stabile Kennungen AF-01, AF-02 ...
- Jede Angriffsflaeche verweist ueber die Kennungen auf mindestens ein Modellelement
  (element_refs) und auf die darueber erreichbaren Assets (erreichbare_assets, FA-06).
- Verweise NUR auf Kennungen, die im Systemmodell existieren.
- Gib je Angriffsflaeche eine kurze Begruendung (ein Satz), warum sie eine ist.
- Erfinde keine Elemente oder Assets.

Antworte ausschliesslich als JSON-Objekt:
{
  "angriffsflaechen": [
    {"id","name","art","element_refs":["E-.."],"erreichbare_assets":["A-.."],"begruendung"}
  ]
}
"""


def _json_aus_text(text: str) -> dict:
    return repariere_json(text, MODELL)


def lade_analysemodell() -> dict:
    """Laedt das wachsende Analysemodell - analysemodell.json, sonst das
    systemmodell.json aus Stufe 1."""
    fortschritt = AUSGABE / "analysemodell.json"
    if fortschritt.exists():
        return json.loads(fortschritt.read_text(encoding="utf-8"))
    stufe1 = AUSGABE / "systemmodell.json"
    if stufe1.exists():
        return json.loads(stufe1.read_text(encoding="utf-8"))
    raise FileNotFoundError("Kein systemmodell.json gefunden - bitte zuerst Stufe 1 (Agent_CISO.py) freigeben.")


def ableite_angriffsflaechen(modell: dict) -> list:
    print("\n[CISO] Leite Angriffsflaechen aus dem Systemmodell ab ...")
    kontext = "SYSTEMMODELL:\n" + json.dumps(modell, ensure_ascii=False, indent=2)
    ergebnis = _json_aus_text(frage_modell(
        AUFTRAG + "\n\n" + kontext, modell=MODELL, max_tokens=MAX_TOKENS))
    return ergebnis.get("angriffsflaechen", [])


if __name__ == "__main__":
    modell = lade_analysemodell()
    flaechen = ableite_angriffsflaechen(modell)

    modell["angriffsflaechen"] = flaechen
    ziel = AUSGABE / "analysemodell.json"
    ziel.write_text(json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n[CISO] {len(flaechen)} Angriffsflaechen abgeleitet. Gespeichert in {ziel.name}.\n")
    for af in flaechen:
        assets = ", ".join(af.get("erreichbare_assets", [])) or "-"
        print(f"  {af.get('id')}: {af.get('name')}  (Elemente: {', '.join(af.get('element_refs', []))} | Assets: {assets})")
