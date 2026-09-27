"""Bericht und Export (Stufe 5): Erzeugt deterministisch einen strukturierten Analysebericht (bericht.md) aus dem Analysemodell und stellt den maschinenlesbaren Export (analysemodell.json) sicher. 
Die Berichtserstellung erfolgt ohne zusätzlichen Modellaufruf und gewährleistet die Konsistenz mit dem Analysemodell. 
Maßnahmenempfehlungen sind bewusst nicht Bestandteil des Untersuchungsumfangs.
"""

import json
from datetime import datetime
from pathlib import Path

from ausgabe import AUSGABE

ORDNER = Path(__file__).resolve().parent

PRIO_RANG = {"kritisch": 0, "hoch": 1, "mittel": 2, "niedrig": 3}


def lade_analysemodell() -> dict:
    pfad = AUSGABE / "analysemodell.json"
    if not pfad.exists():
        raise FileNotFoundError("Kein analysemodell.json - bitte die vorigen Stufen laufen lassen.")
    return json.loads(pfad.read_text(encoding="utf-8"))


def _bewertung_nach_threat(modell: dict) -> dict:
    return {b["threat_ref"]: b for b in modell.get("bewertungen", [])}


def erzeuge_bericht(modell: dict) -> str:
    z = []
    z.append("# Threat Analyse ShopFlow - Bericht")
    z.append(f"\n*Erzeugt am {datetime.now().strftime('%d.%m.%Y %H:%M')} aus dem Analysemodell.*\n")

    # Kennzahlen
    elemente = modell.get("elemente", [])
    flaechen = modell.get("angriffsflaechen", [])
    ti = modell.get("ti_befunde", modell.get("ti_artifacts", []))
    threats = modell.get("bedrohungen", [])
    bew = _bewertung_nach_threat(modell)
    z.append("## Überblick")
    z.append(f"- Modellelemente: {len(elemente)}")
    z.append(f"- Angriffsflächen: {len(flaechen)}")
    z.append(f"- TI-Befunde: {len(ti)}")
    z.append(f"- Bedrohungen: {len(threats)}")

    # Systemmodell
    z.append("\n## 1 Systemmodell")
    z.append("\n**Elemente**\n")
    for e in elemente:
        z.append(f"- `{e.get('id')}` {e.get('name')} ({e.get('art','')}) - {e.get('beschreibung','')}")
    if modell.get("vertrauensgrenzen"):
        z.append("\n**Vertrauensgrenzen**\n")
        for v in modell["vertrauensgrenzen"]:
            z.append(f"- `{v.get('id')}` {v.get('name')} - {v.get('beschreibung','')}")

    # Assets
    z.append("\n## 2 Assets und Schutzziele")
    for a in modell.get("assets", []):
        ziele = ", ".join(a.get("schutzziele", [])) if isinstance(a.get("schutzziele"), list) else a.get("schutzziele", "")
        z.append(f"- `{a.get('id')}` {a.get('name')} (Element {a.get('element_ref')}, "
                 f"Kritikalität: {a.get('kritikalitaet','')}) - Schutzziele: {ziele}. {a.get('begruendung','')}")

    # Angriffsflächen
    z.append("\n## 3 Angriffsflächen")
    for f in flaechen:
        assets = ", ".join(f.get("erreichbare_assets", [])) or "-"
        z.append(f"- `{f.get('id')}` {f.get('name')} - Elemente: {', '.join(f.get('element_refs', []))} | "
                 f"erreichbare Assets: {assets}. {f.get('begruendung','')}")

    # TI-Befunde
    z.append("\n## 4 Threat-Intelligence-Befunde")
    if ti:
        for t in ti:
            z.append(f"- `{t.get('id')}` {t.get('identifier','')} [{t.get('klasse','')}] "
                     f"zu {t.get('surface_ref','')} - {t.get('summary','')}")
            z.append(f"    Beleg: {t.get('source_url','')} (abgerufen {t.get('retrieved_at','')}, "
                     f"Ausnutzung: {t.get('exploitation_status','')})")
    else:
        z.append("- keine TI-Befunde erfasst")

    # Bedrohungen + Bewertung, nach Priorität
    z.append("\n## 5 Bedrohungsverzeichnis mit Bewertung und Priorisierung")
    def sort_key(t):
        b = bew.get(t["id"], {})
        return (PRIO_RANG.get(b.get("prioritaet", "niedrig"), 3), -b.get("score", 0))
    for t in sorted(threats, key=sort_key):
        b = bew.get(t["id"], {})
        prio = b.get("prioritaet", "-")
        score = b.get("score", "-")
        z.append(f"\n### `{t['id']}` {t.get('titel','')}  —  Priorität: **{prio}** (Score {score})")
        z.append(f"- STRIDE: {t.get('stride','')} | Element: {t.get('element_ref','')} | "
                 f"Angriffsfläche: {t.get('surface_ref','')} | Methodik: {t.get('methodik','')}")
        if t.get("ti_refs"):
            z.append(f"- TI-Beleg: {', '.join(t['ti_refs'])}")
        z.append(f"- {t.get('beschreibung','')}")
        if t.get("szenario"):
            z.append(f"- Angriffsszenario: {t['szenario']}")
        if t.get("voraussetzungen"):
            vor = t["voraussetzungen"]
            vor = "; ".join(map(str, vor)) if isinstance(vor, list) else vor
            z.append(f"- Voraussetzungen: {vor}")
        if t.get("auswirkung"):
            z.append(f"- Auswirkung: {t['auswirkung']}")
        if b:
            z.append(f"- Bewertung: Eintrittswahrscheinlichkeit {b.get('eintrittswahrscheinlichkeit','')} "
                     f"({b.get('ew_begruendung','')}); Auswirkung {b.get('auswirkung','')} "
                     f"({b.get('auswirkung_begruendung','')}); Assets: {', '.join(b.get('asset_refs', [])) or '-'}")

    # Annahmen + offene Punkte
    if modell.get("annahmen"):
        z.append("\n## 6 Annahmen")
        for a in modell["annahmen"]:
            z.append(f"- {a}")
    if modell.get("rueckfragen_nutzer"):
        z.append("\n## 7 Offene Rückfragen an den Nutzer")
        for r in modell["rueckfragen_nutzer"]:
            z.append(f"- {r}")

    # Quellenverzeichnis
    z.append("\n## 8 Quellenverzeichnis (Threat Intelligence)")
    quellen = sorted({(t.get("source_name", ""), t.get("source_url", "")) for t in ti})
    if quellen:
        for name, url in quellen:
            z.append(f"- {name}: {url}")
    else:
        z.append("- keine")

    return "\n".join(z)


if __name__ == "__main__":
    modell = lade_analysemodell()
    bericht = erzeuge_bericht(modell)
    (AUSGABE / "bericht.md").write_text(bericht, encoding="utf-8")
    # Export ist das Analysemodell selbst (bereits gespeichert); Kopie mit sprechendem Namen:
    (AUSGABE / "export_analysemodell.json").write_text(
        json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")

    print("[Bericht] bericht.md geschrieben (lesbarer Bericht).")
    print("[Export]  export_analysemodell.json geschrieben (maschinenlesbar).")
