"""Der CISO-Agent - analytischer Kern und Orchestrator.

Der CISO erhaelt EIN Eingabedokument (Architekturdiagramm ODER Systembeschreibung),
analysiert es selbst und entwickelt daraus einen Entwurf des Systemmodells. Erkennt er
dabei eine Informationsluecke, richtet er eine gezielte Rueckfrage an die Instanz mit dem
tieferen Wissen:

  - Architekt-Agent  : detailliertes Architekturwissen / -diagramm
  - SW-Engineer-Agent: Wissen ueber das System (Datenfluesse, Datenkategorien,
                       Implementierung, Sicherheitseigenschaften)
  - Nutzer           : was nur der Nutzer beantworten kann

Ein unabhaengiger Pruef-Agent begutachtet anschliessend das Systemmodell (nur lesend) und
dokumentiert Maengel in einem Pruefbericht. Systemmodell und Pruefbericht gehen an den
Nutzer (Human-in-the-Loop, Freigabepunkt 1): freigeben, ueberarbeiten lassen oder ablehnen.

Sterntopologie: NUR der CISO spricht mit den Fachagenten und schreibt in das Analysemodell.

Nach der Freigabe orchestriert der CISO die weitere Kette (siehe __main__):
Angriffsflaechen -> Threat Intelligence -> Bedrohungen (identifizieren und analysieren)
-> Bewertung und Priorisierung -> Bericht. Im Frontend (app.py) kommt vor der Bewertung
ein zweiter Freigabepunkt fuer die Bedrohungen hinzu (FA-17).
"""

import json
import re
from pathlib import Path

from llm import frage_modell, frage_modell_mit_bild, repariere_json
from ausgabe import AUSGABE
from modelle import modell_fuer, alle_zuordnungen
from Agent_Software_Engineer import frage_sw_engineer
from Agent_Architekt import frage_architekt, finde_diagramm
from Agent_Pruefer import pruefe_systemmodell
from CISO_Angriffsflaechen import ableite_angriffsflaechen
from Agent_TI import recherchiere, lade_quellen, speichere_ti_befunde
from CISO_Bedrohungen import bedrohungen_je_flaeche, lade_methodik
from CISO_Bewertung import bewerte, lade_scoring, priorisierte_liste
from CISO_Bericht import erzeuge_bericht


MODELL = modell_fuer("ciso")      # Reasoning-Kern (zentral in Config/modelle.json)
EINGABE = "diagramm"              # "diagramm" (Bild) oder "beschreibung" (Text)
MAX_KLAERUNGEN = 8                # so viele offene Punkte klaert der CISO aktiv
MAX_TOKENS = 16000                # Obergrenze der Antwortlaenge, damit das Systemmodell nicht abgeschnitten wird


AUFTRAG_ENTWURF = """Du bist der CISO-Agent, der analytische Kern eines Threat-Analyse-
Systems. Du erhaeltst EIN Eingabedokument (siehe unten bzw. als Bild) und analysierst es.
Entwickle daraus einen ENTWURF eines strukturierten Systemmodells.

Regeln:
- Vergib stabile Kennungen: Elemente E-01 ...; Datenfluesse DF-01 ...;
  Vertrauensgrenzen VG-1 ...; Assets A-01 ...
- Modelliere, was das Dokument hergibt.
- Fuer alles, was das Dokument NICHT hergibt, trage einen OFFENEN PUNKT ein - mit einer
  konkreten Frage und der Angabe, wen du befragen solltest:
    "architekt"   = Struktur/Architekturdetails (Komponenten, Schichten, Zonen,
                    Vertrauensgrenzen) - der Architekt hat detailliertes Architekturwissen.
    "sw_engineer" = Wissen ueber das System (Datenfluesse, Datenkategorien,
                    Implementierung, Sicherheitseigenschaften).
    "nutzer"      = nur der Nutzer kann es wissen.
- Denk daran: Ein Architekturdiagramm zeigt selten Datenfluesse im Detail, Daten-
  kategorien oder Sicherheitseigenschaften - solche fehlenden Angaben gehoeren als
  offene Punkte an den SW-Engineer oder den Nutzer.
- Halte alle Beschreibungen und Begruendungen knapp (je ein kurzer Satz).
- Erfinde nichts.

Antworte ausschliesslich als JSON-Objekt:
{
  "elemente": [{"id","name","art","beschreibung"}],
  "datenfluesse": [{"id","quelle","ziel","daten","ueberschreitet_grenze"}],
  "vertrauensgrenzen": [{"id","name","beschreibung"}],
  "assets": [{"id","name","element_ref","schutzziele","kritikalitaet","begruendung"}],
  "annahmen": ["..."],
  "offene_punkte": [{"frage","frage_an"}]
}
"""


AUFTRAG_FINAL = """Du bist der CISO-Agent. Du hast einen Entwurf des Systemmodells entwickelt
und offene Punkte durch Rueckfragen an die Fachagenten geklaert. Setze jetzt das FINALE
Systemmodell um.

- Arbeite die Klaerungen ein: bestaetigte Angaben werden Teil des Modells (ergaenze
  fehlende Datenfluesse, Datenkategorien, Assets), gemeldete Luecken bleiben Luecken.
- Was weiterhin ungeklaert ist oder nur der Nutzer beantworten kann, kommt unter
  "rueckfragen_nutzer". Behalte die Kennungen aus dem Entwurf bei.

Antworte ausschliesslich als JSON-Objekt:
{
  "elemente": [{"id","name","art","beschreibung"}],
  "datenfluesse": [{"id","quelle","ziel","daten","ueberschreitet_grenze"}],
  "vertrauensgrenzen": [{"id","name","beschreibung"}],
  "assets": [{"id","name","element_ref","schutzziele","kritikalitaet","begruendung"}],
  "annahmen": ["..."],
  "rueckfragen_nutzer": ["..."],
  "klaerungsprotokoll": [{"frage","gefragt_wen","antwort"}]
}
"""


AUFTRAG_UEBERARBEITUNG = """Du bist der CISO-Agent. Ein unabhaengiger Pruef-Agent hat dein
Systemmodell kritisiert. Ueberarbeite das Modell so, dass die genannten Maengel behoben
sind:
- Fehlende Elemente oder Datenfluesse ergaenzen - aber nur, wenn belegbar; sonst als
  offenen Punkt bzw. Rueckfrage an den Nutzer fuehren.
- Still angenommene (Sicherheits-)Eigenschaften in Luecken/Rueckfragen umwandeln.
- Fehlende Asset-Begruendungen ergaenzen.
- Erfinde nichts. Behalte die vorhandenen Kennungen bei.

Halte alle Beschreibungen und Begruendungen knapp (je ein kurzer Satz).

Gib das ueberarbeitete FINALE Systemmodell im GLEICHEN JSON-Format zurueck wie zuvor
(mit "elemente", "datenfluesse", "vertrauensgrenzen", "assets", "annahmen",
"rueckfragen_nutzer", "klaerungsprotokoll") - ausschliesslich als JSON-Objekt, ohne
Vor- oder Nachtext.
"""


AUFTRAG_ANTWORTEN = """Du bist der CISO-Agent. Der Nutzer hat offene Rueckfragen zum
Systemmodell beantwortet (Human-in-the-Loop). Arbeite die Antworten in das Modell ein:
schliesse die betroffenen Luecken, ergaenze die nun bekannten Angaben (Elemente,
Datenfluesse, Vertrauensgrenzen, Assets), und entferne die beantworteten Punkte aus
"rueckfragen_nutzer".

- Ergaenze NUR, was durch die Antworten des Nutzers belegt ist. Erfinde nichts.
- Behalte die vorhandenen Kennungen bei.

Gib das aktualisierte FINALE Systemmodell im GLEICHEN JSON-Format zurueck
(mit "elemente", "datenfluesse", "vertrauensgrenzen", "assets", "annahmen",
"rueckfragen_nutzer") - ausschliesslich als JSON-Objekt.
"""


def _json_aus_text(text: str) -> dict:
    return repariere_json(text, MODELL)


def _analysiere_eingabe() -> dict:
    """Der CISO analysiert sein Eingabedokument und entwickelt den Entwurf."""
    if EINGABE == "diagramm":
        diagramm = finde_diagramm()
        print(f"\n[CISO] Analysiere Eingabe (Diagramm): {Path(diagramm).name}")
        return _json_aus_text(frage_modell_mit_bild(
            AUFTRAG_ENTWURF, diagramm, modell=MODELL, max_tokens=MAX_TOKENS))
    elif EINGABE == "beschreibung":
        from Agent_Software_Engineer import lade_systembeschreibung
        text = lade_systembeschreibung()
        print("\n[CISO] Analysiere Eingabe (Systembeschreibung)")
        prompt = AUFTRAG_ENTWURF + "\n\nEINGABEDOKUMENT:\n\"\"\"\n" + text + "\n\"\"\""
        return _json_aus_text(frage_modell(prompt, modell=MODELL, max_tokens=MAX_TOKENS))
    else:
        raise ValueError(f"Unbekannter EINGABE-Typ: {EINGABE}")


def _frage_spezialist(wen: str, frage: str) -> dict:
    """Leitet eine Rueckfrage an die zustaendige Instanz."""
    if wen == "architekt":
        print(f"\n[CISO -> Architekt] {frage}")
        return frage_architekt(finde_diagramm(), frage)
    elif wen == "sw_engineer":
        print(f"\n[CISO -> SW-Engineer] {frage}")
        return frage_sw_engineer(frage)
    else:
        return {"antwort": "(nur der Nutzer kann dies beantworten)"}


def entwickle_systemmodell() -> dict:
    # Schritt 1: CISO analysiert sein Eingabedokument -> Entwurf + offene Punkte.
    entwurf = _analysiere_eingabe()

    # Schritt 2: jede erkannte Luecke an die richtige Instanz.
    klaerungen = []
    for punkt in entwurf.get("offene_punkte", [])[:MAX_KLAERUNGEN]:
        frage = punkt.get("frage", "")
        wen = punkt.get("frage_an", "nutzer")
        if wen == "nutzer":
            klaerungen.append({"frage": frage, "gefragt_wen": "nutzer", "antwort": "(offen)"})
            continue
        antw = _frage_spezialist(wen, frage)
        klaerungen.append({"frage": frage, "gefragt_wen": wen, "antwort": antw})

    # Schritt 3: finales Modell aus Entwurf + Klaerungen.
    print("\n[CISO] Setze finales Systemmodell aus Entwurf + Klaerungen um ...")
    kontext = (
        "ENTWURF:\n" + json.dumps(entwurf, ensure_ascii=False, indent=2)
        + "\n\nKLAERUNGEN:\n" + json.dumps(klaerungen, ensure_ascii=False, indent=2)
    )
    modell = _json_aus_text(frage_modell(
        AUFTRAG_FINAL + "\n\n" + kontext, modell=MODELL, max_tokens=MAX_TOKENS))
    # Den echten Dialog CISO <-> Fachagenten mitschreiben (Nachvollziehbarkeit NFA-01).
    modell["fachagenten_dialog"] = klaerungen
    # Rolle-zu-Modell-Zuordnung als Laufmanifest festhalten (NFA-01).
    modell["modell_zuordnung"] = alle_zuordnungen()
    return modell


def schreibe_pruefbericht(bericht: dict) -> Path:
    """Schreibt den Prueffund als lesbaren Bericht (Datei), der dem Nutzer
    zusammen mit dem Systemmodell vorgelegt wird."""
    zeilen = ["# Pruefbericht zum Systemmodell", ""]
    ergebnis = "BESTANDEN" if bericht.get("bestanden") else "NICHT BESTANDEN"
    zeilen.append(f"Ergebnis der unabhaengigen Pruefung: {ergebnis}")
    zeilen += ["", "## Festgestellte Maengel"]
    maengel = bericht.get("maengel", [])
    if maengel:
        for m in maengel:
            zeilen.append(f"- [{m.get('schwere','?')}] {m.get('bezug','')}: {m.get('problem','')}")
    else:
        zeilen.append("- keine")
    zeilen += ["", "## Empfehlungen"]
    empf = bericht.get("empfehlungen", [])
    if empf:
        for e in empf:
            zeilen.append(f"- {e}")
    else:
        zeilen.append("- keine")

    pfad = AUSGABE / "pruefbericht.md"
    pfad.write_text("\n".join(zeilen), encoding="utf-8")
    return pfad


def ueberarbeite(modell: dict, bericht: dict) -> dict:
    """Optionaler, vom Nutzer ausgeloester Korrekturzyklus: Der CISO ueberarbeitet
    das Modell EINMAL anhand des Pruefberichts. Scheitert das Auslesen, bleibt das
    Modell unveraendert (best effort)."""
    print("\n[CISO] Ueberarbeite das Modell anhand des Pruefberichts ...")
    kontext = (
        "URSPRUENGLICHES MODELL:\n" + json.dumps(modell, ensure_ascii=False, indent=2)
        + "\n\nBEANSTANDUNGEN DES PRUEFERS:\n"
        + json.dumps(bericht, ensure_ascii=False, indent=2)
    )
    try:
        return _json_aus_text(frage_modell(
            AUFTRAG_UEBERARBEITUNG + "\n\n" + kontext, modell=MODELL, max_tokens=MAX_TOKENS))
    except Exception as exc:
        print(f"[CISO] Ueberarbeitung nicht lesbar ({type(exc).__name__}); "
              f"behalte das bisherige Modell.")
        return modell


def ueberarbeite_mit_antworten(modell: dict, antworten: dict) -> dict:
    """Arbeitet die vom Nutzer beantworteten Rueckfragen in das Systemmodell ein
    (Human-in-the-Loop). antworten: {frage: antwort}. Scheitert das Auslesen,
    bleibt das Modell unveraendert."""
    dialog = "\n".join(f"Frage: {f}\nAntwort des Nutzers: {a}"
                       for f, a in antworten.items() if a and str(a).strip())
    if not dialog:
        return modell
    print("\n[CISO] Arbeite die Antworten des Nutzers ein ...")
    kontext = ("SYSTEMMODELL:\n" + json.dumps(modell, ensure_ascii=False, indent=2)
               + "\n\nBEANTWORTETE RUECKFRAGEN:\n" + dialog)
    try:
        neu = _json_aus_text(frage_modell(
            AUFTRAG_ANTWORTEN + "\n\n" + kontext, modell=MODELL, max_tokens=MAX_TOKENS))
        neu.setdefault("fachagenten_dialog", modell.get("fachagenten_dialog", []))
        return neu
    except Exception as exc:
        print(f"[CISO] Einarbeiten nicht lesbar ({type(exc).__name__}); Modell unveraendert.")
        return modell


def freigabepunkt(modell: dict, bericht: dict) -> str:
    """Human-in-the-Loop: Der Nutzer sieht Modell UND Pruefbericht und entscheidet.
    Rueckgabe: 'j' (freigeben), 'u' (ueberarbeiten lassen), 'n' (ablehnen)."""
    print("\n" + "=" * 60)
    print("SYSTEMMODELL - bitte pruefen:")
    print("=" * 60)
    print(json.dumps(modell, ensure_ascii=False, indent=2))
    print("\n" + "-" * 60)
    print("PRUEFBERICHT des unabhaengigen Pruef-Agenten:")
    print("-" * 60)
    print(f"Ergebnis: {'BESTANDEN' if bericht.get('bestanden') else 'NICHT BESTANDEN'}")
    for m in bericht.get("maengel", []):
        print(f"  - [{m.get('schwere','?')}] {m.get('bezug','')}: {m.get('problem','')}")
    print("=" * 60)
    while True:
        wahl = input("\n[j] freigeben  [u] ueberarbeiten lassen  [n] ablehnen: ").strip().lower()
        if wahl in ("j", "u", "n"):
            return wahl


if __name__ == "__main__":
    modell = entwickle_systemmodell()

    while True:
        # Analysemodell persistieren, damit der Pruef-Agent es LESEND pruefen kann.
        (AUSGABE / "analysemodell.json").write_text(
            json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")
        # Pruef-Agent liest das Systemmodell aus dem Analysemodell und schreibt einen Bericht.
        print("\n[Pruefer] Begutachte das Systemmodell ...")
        bericht = pruefe_systemmodell()
        modell["pruefprotokoll"] = modell.get("pruefprotokoll", []) + [bericht]
        pfad = schreibe_pruefbericht(bericht)
        print(f"[Pruefer] Pruefbericht geschrieben: {pfad.name} "
              f"({'bestanden' if bericht.get('bestanden') else 'nicht bestanden'})")

        # Modell + Bericht gehen an den Nutzer.
        wahl = freigabepunkt(modell, bericht)
        if wahl == "j":
            def sichern():
                (AUSGABE / "analysemodell.json").write_text(
                    json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")

            (AUSGABE / "systemmodell.json").write_text(
                json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")
            print("\n[CISO] Systemmodell freigegeben. Der CISO fuehrt nun die Analyse durch.")

            # Der CISO orchestriert die gesamte Kette (jede Stufe eine Rollenfunktion).
            # Stufe 2: Angriffsflaechen
            modell["angriffsflaechen"] = ableite_angriffsflaechen(modell)
            sichern()
            # Stufe TI: Threat Intelligence (Standard: erste Angriffsflaeche, Token sparen)
            modell["ti_befunde"] = recherchiere(modell, lade_quellen())
            speichere_ti_befunde(modell["ti_befunde"], modell.get("ti_diagnose"))
            sichern()
            # Stufe 3: Bedrohungen
            bedrohungen, abdeckung = bedrohungen_je_flaeche(modell, lade_methodik())
            modell["bedrohungen"], modell["abdeckung"] = bedrohungen, abdeckung
            sichern()
            # Stufe 4: Bewertung + Priorisierung
            scoring = lade_scoring()
            modell["bewertungen"] = bewerte(modell, scoring)
            modell["scoring_schema"] = scoring
            sichern()
            # Stufe 5: Bericht + Export
            (AUSGABE / "bericht.md").write_text(erzeuge_bericht(modell), encoding="utf-8")

            liste = priorisierte_liste(modell)
            print(f"\n[CISO] Analyse abgeschlossen: {len(modell['angriffsflaechen'])} "
                  f"Angriffsflaechen, {len(modell.get('ti_befunde', []))} TI-Befunde, "
                  f"{len(bedrohungen)} Bedrohungen.")
            print("Priorisierte Bedrohungsliste (Top 10):")
            for r in liste[:10]:
                print(f"  [{r['prioritaet']:>8}] {r['id']} {r['titel']}  (Score {r['score']})")
            print("\nGespeichert: analysemodell.json (Export) und bericht.md (Bericht).")
            break
        elif wahl == "u":
            modell = ueberarbeite(modell, bericht)   # ein vom Nutzer ausgeloester Zyklus
            continue
        else:
            print("\n[CISO] Nicht freigegeben. Nichts gespeichert.")
            break
