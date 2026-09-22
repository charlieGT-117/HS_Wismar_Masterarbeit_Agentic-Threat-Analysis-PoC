"""Der Pruef-Agent (Reflexionsmuster; unterstuetzt NFA-01 Nachvollziehbarkeit und NFA-03 Kontrollierbarkeit).

Prueft das vom CISO entwickelte Systemmodell KRITISCH, bevor es dem Nutzer zur
Freigabe vorgelegt wird. Zweite Pruefebene neben der strukturellen Schema-Pruefung:
Das Schema prueft maschinell die Verweise; dieser Agent prueft semantisch die
Qualitaet und Ehrlichkeit des Modells.

Der Pruefer nutzt bewusst ein eigenes Modell - so beurteilt nicht dasselbe Modell
seine eigene Ausgabe (unabhaengige Reflexion).
"""

import json
import re
from llm import frage_modell, repariere_json
from ausgabe import AUSGABE
from modelle import modell_fuer, anbieter_fuer


# Eigenes Modell fuer die unabhaengige Pruefung (kann vom CISO-Modell abweichen).
ANBIETER = anbieter_fuer("pruefer")
MODELL = modell_fuer("pruefer")


AUFTRAG = """Du bist der Pruef-Agent in einem Threat-Analyse-System. Du erhaeltst ein
Systemmodell, das der CISO-Agent entwickelt hat, und pruefst es KRITISCH und
unabhaengig, bevor es einem Nutzer zur Freigabe vorgelegt wird. Du bist streng,
aber fair.

Pruefe entlang dieser Checkliste:
1. EHRLICHKEIT DER LUECKEN: Werden fehlende Angaben als Annahme, offener Punkt oder
   Rueckfrage gefuehrt - oder wird irgendwo eine konkrete (Sicherheits-)Eigenschaft
   behauptet, die nicht belegt sein kann? Jede stillschweigend gefuellte Luecke ist
   ein schwerer Mangel.
2. ASSET-QUALITAET: Hat jedes Asset Schutzziele, eine Kritikalitaet UND eine
   nachvollziehbare Begruendung? Fehlt eine Begruendung oder wirkt sie willkuerlich,
   ist das ein Mangel.
3. DATENFLUSS-KONSISTENZ: Verweisen Datenfluesse auf existierende Elemente (Kennungen)?
   Sind grenzueberschreitende Fluesse als solche markiert?
4. VERTRAUENSGRENZEN: Sind sie adressiert - entweder modelliert oder als offener Punkt
   vermerkt? Ein voelliges Fehlen ohne Hinweis ist ein Mangel.
5. PLAUSIBILITAET / VOLLSTAENDIGKEIT: Fehlt ein Element oder Datenfluss, den man bei
   einem solchen System klar erwarten wuerde? Nutze dein Fachwissen, aber unterscheide
   sauber zwischen "fehlt eindeutig" und "waere denkbar".

Antworte ausschliesslich als JSON-Objekt:
{
  "bestanden": true oder false,
  "maengel": [{"bezug": "Kennung oder Bereich", "problem": "...", "schwere": "hoch|mittel|niedrig"}],
  "empfehlungen": ["konkrete Verbesserungsvorschlaege"]
}

Regel fuer "bestanden": false, sobald mindestens ein Mangel der Schwere "hoch" vorliegt
oder mehrere der Schwere "mittel". Sonst true.
"""


def _json_aus_text(text: str) -> dict:
    return repariere_json(text, MODELL)


def lade_systemmodell() -> dict:
    """Der Pruef-Agent liest das zu pruefende Systemmodell selbst aus dem gemeinsamen
    Analysemodell (nur lesend, kein Schreibrecht)."""
    pfad = AUSGABE / "analysemodell.json"
    if not pfad.exists():
        raise FileNotFoundError("Kein analysemodell.json - bitte zuerst das Systemmodell entwickeln.")
    return json.loads(pfad.read_text(encoding="utf-8"))


def pruefe_systemmodell(modell: dict | None = None) -> dict:
    """Prueft das Systemmodell und gibt {bestanden, maengel, empfehlungen} zurueck.

    Ohne Argument liest der Pruef-Agent das Systemmodell selbst (lesend) aus dem
    Analysemodell (analysemodell.json). Ein uebergebenes Modell wird bevorzugt genutzt.
    """
    if modell is None:
        modell = lade_systemmodell()
    prompt = (
        AUFTRAG
        + "\n\nZU PRUEFENDES SYSTEMMODELL:\n"
        + json.dumps(modell, ensure_ascii=False, indent=2)
    )
    return _json_aus_text(frage_modell(prompt, anbieter=ANBIETER, modell=MODELL,
                                       max_tokens=8000))
