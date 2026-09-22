"""Stufe 3: Bedrohungen identifizieren UND analysieren (CISO, KF-4 / FA-12 bis FA-16).

Analyse je Bedrohung (FA-15): Angriffsszenario, Voraussetzungen und moegliche Auswirkung
werden zusammen mit der Identifikation erzeugt (ein Aufruf je Angriffsflaeche).

Nimmt das Analysemodell (Systemmodell + Angriffsflaechen + TI-Befunde) und
identifiziert je Angriffsflaeche die Bedrohungen. Pro Angriffsflaeche ein eigener
Modellaufruf - kleine Ausgaben, robust gegen das Token-Limit (LL-1).

Die Methodik ist NICHT im Code verdrahtet (FA-14): Die Bausteine stehen in
methodik.json. Der CISO waehlt je Angriffsflaeche einen Baustein und begruendet die
Wahl. Liegen zur Angriffsflaeche TI-Befunde vor, kann er "quellengeleitet" oder
"kombiniert" waehlen und die Bedrohung auf den Befund zurueckbinden (ti_refs).

Jede Bedrohung traegt eine STRIDE-Kategorie und eine knappe Begruendung (dosiertes
Chain-of-Thought, LL-3). Auch Flaechen ohne Bedrohung erhalten einen Abdeckungsnachweis.
"""

import json
import re
from pathlib import Path

from llm import frage_modell, repariere_json
from ausgabe import AUSGABE, CONFIG
from modelle import modell_fuer

MODELL = modell_fuer("ciso")
MAX_TOKENS = 8000
ORDNER = Path(__file__).resolve().parent


def _json_aus_text(text: str) -> dict:
    return repariere_json(text, MODELL)


def lade_analysemodell() -> dict:
    pfad = AUSGABE / "analysemodell.json"
    if not pfad.exists():
        raise FileNotFoundError("Kein analysemodell.json - bitte zuerst Stufe 2 laufen lassen.")
    return json.loads(pfad.read_text(encoding="utf-8"))


def lade_methodik() -> dict:
    return json.loads((CONFIG / "methodik.json").read_text(encoding="utf-8"))


def _methodik_text(methodik: dict) -> str:
    zeilen = ["VERFUEGBARE METHODIKBAUSTEINE (waehle je Angriffsflaeche einen):"]
    for b in methodik.get("bausteine", []):
        zeilen.append(f'- id "{b["id"]}" ({b.get("name","")}): {b.get("wann","")}')
        for kat in b.get("kategorien", []):
            zeilen.append(f'    * {kat["key"]} {kat["name"]}: {kat["frage"]}')
    return "\n".join(zeilen)


def _auftrag(methodik: dict) -> str:
    stride_pflicht = ("Ordne JEDER Bedrohung zusaetzlich eine STRIDE-Kategorie zu."
                      if methodik.get("stride_zuordnung_pflicht") else "")
    return f"""Du bist der CISO-Agent. Dir liegen das Systemmodell (Elemente, Assets), EINE
Angriffsflaeche und - falls vorhanden - die dazu recherchierten TI-Befunde vor.
Identifiziere die Bedrohungen fuer genau diese Angriffsflaeche.

{_methodik_text(methodik)}

Vorgehen (FA-14): Waehle den passenden Baustein (per id) und begruende die Wahl kurz.
- Liegen TI-Befunde vor, kannst du "quellengeleitet" oder "kombiniert" waehlen und die
  Bedrohung auf den Befund zuruueckbinden (ti_refs = Liste der TI-Kennungen).
- Liegen keine vor, ist meist "stride" angemessen (ti_refs bleibt leer).

Fuer jede Bedrohung:
  - titel, beschreibung (knapp)
  - stride: die STRIDE-Kategorie als Name
  - element_ref: betroffenes Element (Kennung aus dem Systemmodell, muss existieren)
  - ti_refs: Liste der belegenden TI-Kennungen (z. B. ["TI-01"]) oder leer
  - begruendung: EIN Satz, warum diese Bedrohung besteht.
  ANALYSE der Bedrohung (FA-15, je ein knapper Satz, konkret auf dieses System bezogen):
  - szenario: ein plausibles Angriffsszenario (wie ein Angreifer konkret vorgeht)
  - voraussetzungen: welche Voraussetzungen dafuer erfuellt sein muessen
  - auswirkung: die moegliche Auswirkung auf das System bzw. die betroffenen Assets
{stride_pflicht}

Wird KEINE Bedrohung gefunden, gib eine leere Liste zurueck. Erfinde keine Elemente.

Antworte ausschliesslich als JSON-Objekt:
{{
  "methodik": "<baustein-id>",
  "methodik_begruendung": "...",
  "bedrohungen": [{{"titel","beschreibung","stride","element_ref","ti_refs","begruendung",
                   "szenario","voraussetzungen","auswirkung"}}]
}}
"""


def _kontext(modell: dict, flaeche: dict, ti_zur_flaeche: list) -> str:
    schlank = {
        "elemente": modell.get("elemente", []),
        "assets": modell.get("assets", []),
        "angriffsflaeche": flaeche,
        "ti_befunde": ti_zur_flaeche,
    }
    return "SYSTEMMODELL (Auszug) + ANGRIFFSFLAECHE + TI-BEFUNDE:\n" + json.dumps(
        schlank, ensure_ascii=False, indent=2)


def bedrohungen_je_flaeche(modell: dict, methodik: dict,
                           nur_ids: list | None = None, start_index: int = 0) -> tuple[list, list]:
    """Identifiziert und analysiert Bedrohungen je Angriffsflaeche.

    nur_ids: nur diese Angriffsflaechen bearbeiten (sonst alle).
    start_index: fortlaufende Bedrohungsnummerierung ab hier (fuer inkrementelle Laeufe).
    """
    auftrag = _auftrag(methodik)
    alle = modell.get("angriffsflaechen", [])
    flaechen = [f for f in alle if not nur_ids or f.get("id") in nur_ids]
    ti_alle = modell.get("ti_befunde", modell.get("ti_artifacts", []))
    bedrohungen, abdeckung = [], []
    zaehler = start_index

    for flaeche in flaechen:
        af_id = flaeche.get("id", "AF-?")
        ti_zur_flaeche = [t for t in ti_alle if t.get("surface_ref") == af_id]
        print(f"\n[CISO] Bedrohungen fuer {af_id} ({flaeche.get('name','')}) - "
              f"{len(ti_zur_flaeche)} TI-Befund(e) ...")
        try:
            ergebnis = _json_aus_text(frage_modell(
                auftrag + "\n\n" + _kontext(modell, flaeche, ti_zur_flaeche),
                modell=MODELL, max_tokens=MAX_TOKENS))
        except Exception as exc:
            print(f"   uebersprungen ({type(exc).__name__}).")
            abdeckung.append({"surface_ref": af_id, "methodik": "-",
                              "methodik_begruendung": "Aufruf fehlgeschlagen",
                              "bedrohungen": [], "geprueft": False})
            continue

        gefundene = ergebnis.get("bedrohungen", [])
        ids_dieser_flaeche = []
        for b in gefundene:
            zaehler += 1
            tid = f"T-{zaehler:02d}"
            ids_dieser_flaeche.append(tid)
            bedrohungen.append({
                "id": tid,
                "titel": b.get("titel", ""),
                "beschreibung": b.get("beschreibung", ""),
                "stride": b.get("stride", ""),
                "element_ref": b.get("element_ref", ""),
                "surface_ref": af_id,
                "ti_refs": b.get("ti_refs", []) or [],
                "methodik": ergebnis.get("methodik", ""),
                "begruendung": b.get("begruendung", ""),
                "szenario": b.get("szenario", ""),
                "voraussetzungen": b.get("voraussetzungen", ""),
                "auswirkung": b.get("auswirkung", ""),
            })

        abdeckung.append({
            "surface_ref": af_id,
            "methodik": ergebnis.get("methodik", ""),
            "methodik_begruendung": ergebnis.get("methodik_begruendung", ""),
            "bedrohungen": ids_dieser_flaeche,
            "geprueft": True,
        })
        print(f"   {len(gefundene)} Bedrohung(en), Methodik: {ergebnis.get('methodik','?')}")

    return bedrohungen, abdeckung


if __name__ == "__main__":
    modell = lade_analysemodell()
    methodik = lade_methodik()
    bedrohungen, abdeckung = bedrohungen_je_flaeche(modell, methodik)

    modell["bedrohungen"] = bedrohungen
    modell["abdeckung"] = abdeckung
    (AUSGABE / "analysemodell.json").write_text(
        json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")

    von_stride, gewaehlt = {}, {}
    for b in bedrohungen:
        von_stride[b["stride"]] = von_stride.get(b["stride"], 0) + 1
    for a in abdeckung:
        gewaehlt[a.get("methodik", "-")] = gewaehlt.get(a.get("methodik", "-"), 0) + 1

    print(f"\n[CISO] {len(bedrohungen)} Bedrohungen ueber {len(abdeckung)} Angriffsflaechen.")
    print("Gewaehlte Methodik je Flaeche:", dict(gewaehlt))
    print("STRIDE-Verteilung:", dict(von_stride))
    print("Gespeichert in analysemodell.json.")
