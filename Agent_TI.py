"""Threat-Intelligence-Agent: Recherchiert im Auftrag des CISO-Agenten aktuelle Bedrohungsinformationen je Angriffsfläche. 
Er wählt eigenständig geeignete Quellen anhand der Konfiguration (quellen.json) und ihrer Abstraktionsebene aus, führt eine Live-Webrecherche durch und dokumentiert jeden Befund mit einer überprüfbaren Quell-URL. 
Der TI-Agent verfügt als einzige Rolle über einen ausschließlich lesenden externen Zugriff.  
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from llm import frage_modell_websuche, repariere_json
from ausgabe import AUSGABE, CONFIG
from modelle import modell_fuer

MODELL = modell_fuer("ti_agent")
ORDNER = Path(__file__).resolve().parent
MAX_TI_FLAECHEN = 1   # zum Token-Sparen: nur eine Angriffsflaeche live recherchieren


def _json_aus_text(text: str) -> dict:
    return repariere_json(text, MODELL)


def lade_analysemodell() -> dict:
    pfad = AUSGABE / "analysemodell.json"
    if not pfad.exists():
        raise FileNotFoundError("Kein analysemodell.json - bitte zuerst Stufe 2 laufen lassen.")
    return json.loads(pfad.read_text(encoding="utf-8"))


def speichere_ti_befunde(befunde: list, diagnose: list | None = None) -> None:
    """Legt die TI-Befunde zusaetzlich als eigenes, lesbares Artefakt ab
    (Output/ti_befunde.json) - Teil der Wissensbasis. Die analysemodell.json bleibt
    die Quelle, aus der der CISO liest."""
    inhalt = {
        "erzeugt_am": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "anzahl": len(befunde),
        "ti_befunde": befunde,
        "diagnose": diagnose or [],
    }
    (AUSGABE / "ti_befunde.json").write_text(
        json.dumps(inhalt, ensure_ascii=False, indent=2), encoding="utf-8")


def lade_quellen() -> dict:
    return json.loads((CONFIG / "quellen.json").read_text(encoding="utf-8"))


def _menue(quellen: dict) -> str:
    return "\n".join(
        f'- id "{q["id"]}" [{q.get("klasse","")}, Ebene: {q.get("abstraktionsebene","")}]: {q["geeignet_fuer"]}'
        for q in quellen.get("quellen", []))


def _auftrag(quellen: dict) -> str:
    return f"""Du bist der Threat-Intelligence-Agent eines Threat-Analyse-Systems.
Zu der unten genannten Angriffsflaeche sollst du belegbare Bedrohungsinformationen
beschaffen.

1. WAEHLE die passende Quelle aus dieser Liste - entscheidend ist die richtige
   Abstraktionsebene:
{_menue(quellen)}
2. RECHERCHIERE dann LIVE im Internet (nutze die Websuche) zu dieser Quelle/Ebene.
3. Uebernimm nur BELEGTE Befunde mit einer echten, in deiner Recherche gefundenen
   Quell-URL. Erfinde keine Kennungen und keine URLs. 1 bis 3 Befunde genuegen.

Antworte am Ende ausschliesslich als JSON-Objekt:
{{"befunde": [
  {{"quelle_id": "<id aus der Liste>",
    "kennung": "z. B. CWE-306 / CAPEC-115 / T1190 / A01:2021 / CVE-2024-xxxx",
    "summary": "kurze Beschreibung des Befunds",
    "source_url": "https://... (echte, recherchierte Quelle)",
    "exploitation_status": "falls bekannt, sonst leer",
    "begruendung": "ein Satz: warum diese Quelle/Ebene passt"}}
]}}
"""


def recherchiere(modell: dict, quellen: dict, nur_ids: list | None = None) -> list:
    """Recherchiert TI je Angriffsflaeche. Ist nur_ids gesetzt (Liste von AF-Kennungen),
    werden nur diese recherchiert - sonst die ersten MAX_TI_FLAECHEN."""
    auftrag = _auftrag(quellen)
    q_nach_id = {q["id"]: q for q in quellen.get("quellen", [])}
    elemente = modell.get("elemente", [])
    alle = modell.get("angriffsflaechen", [])
    if nur_ids:
        flaechen = [f for f in alle if f.get("id") in nur_ids]
    else:
        flaechen = alle[:MAX_TI_FLAECHEN]
    artefakte = []
    diagnose = []
    zaehler = 0

    for flaeche in flaechen:
        af_id = flaeche.get("id", "AF-?")
        print(f"\n[TI] Rechercheauftrag fuer {af_id} ({flaeche.get('name','')}) ...")
        betroffen = [e for e in elemente if e.get("id") in flaeche.get("element_refs", [])]
        kontext = json.dumps({"angriffsflaeche": flaeche, "elemente": betroffen},
                             ensure_ascii=False, indent=2)
        roh = ""
        try:
            roh = frage_modell_websuche(auftrag + "\n\nANGRIFFSFLAECHE + ELEMENTE:\n" + kontext,
                                        modell=MODELL, max_tokens=8000)
            ergebnis = _json_aus_text(roh)
        except Exception as exc:
            hinweis = (f"Antwort nicht als JSON lesbar ({type(exc).__name__}). "
                       "Meist: Websuche nicht aktiviert/kein Guthaben, oder Antwort "
                       "abgeschnitten.")
            print(f"   uebersprungen - {hinweis}")
            diagnose.append({"surface_ref": af_id, "status": "fehler", "anzahl": 0,
                             "hinweis": hinweis, "roh_auszug": (roh or "")[:400]})
            continue

        befunde = ergebnis.get("befunde", [])
        ohne_url = 0
        neu = 0
        for b in befunde:
            if not b.get("source_url"):
                ohne_url += 1
                continue   # ohne Beleg nicht uebernehmen
            zaehler += 1
            neu += 1
            qinfo = q_nach_id.get(b.get("quelle_id", ""), {})
            artefakte.append({
                "id": f"TI-{zaehler:02d}",
                "source_id": b.get("quelle_id", ""),
                "source_name": qinfo.get("name", b.get("quelle_id", "")),
                "klasse": qinfo.get("klasse", ""),
                "abstraktionsebene": qinfo.get("abstraktionsebene", ""),
                "identifier": b.get("kennung", ""),
                "summary": b.get("summary", ""),
                "source_url": b.get("source_url", ""),
                "quellenwahl_begruendung": b.get("begruendung", ""),
                "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "exploitation_status": b.get("exploitation_status", "") or "unbekannt",
                "surface_ref": af_id,
                "is_external_content": True,
                "live_abgefragt": True,
            })
        if neu:
            status, hinweis = "ok", f"{neu} belegte Befunde uebernommen."
        elif ohne_url:
            status, hinweis = "ohne_beleg", (f"{ohne_url} Befund(e) ohne Quell-URL - "
                                             "ohne Beleg nicht uebernommen.")
        else:
            status, hinweis = "leer", "Modell lieferte keine Befunde zu dieser Flaeche."
        diagnose.append({"surface_ref": af_id, "status": status,
                         "anzahl": neu, "hinweis": hinweis})
        print(f"   {len(befunde)} Befund(e) roh, {neu} mit Beleg uebernommen.")

    modell["ti_diagnose"] = diagnose
    return artefakte


if __name__ == "__main__":
    modell = lade_analysemodell()
    quellen = lade_quellen()
    artefakte = recherchiere(modell, quellen)

    modell["ti_befunde"] = artefakte
    (AUSGABE / "analysemodell.json").write_text(
        json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")
    # Zusaetzlich als eigenes, lesbares Beleg-Artefakt (Wissensbasis).
    speichere_ti_befunde(artefakte, modell.get("ti_diagnose"))

    genutzte = sorted({a["klasse"] for a in artefakte if a.get("klasse")})
    print(f"\n[TI] {len(artefakte)} TI-Artefakte live recherchiert. Genutzte Klassen: {', '.join(genutzte)}")
    for a in artefakte:
        print(f"  {a['id']}: {a['identifier']} [{a['source_id']}/{a['klasse']}] -> {a['surface_ref']}")
        print(f"       Beleg: {a['source_url']}")
    print("\nGespeichert in analysemodell.json.")
