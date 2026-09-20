"""Der Architekt-Agent.

Rolle im Ablauf: Der CISO befragt ihn, um das Systemmodell aufzubauen,
speziell zu Komponentenschnitt, Schichten und Vertrauensgrenzen.

Belegt FA-01: der Prototyp kann eine diagrammbasierte Beschreibung uebernehmen.
"""

import json
import re
from pathlib import Path
from llm import frage_modell_mit_bild, repariere_json
from modelle import modell_fuer


MODELL = modell_fuer("architekt")


AUFTRAG = """Du bist der Architekt-Agent im Threat-Analyse-System. Du hast die Architektur entworfen. Dir liegt das Architekturdiagramm als
Bild vor. Du kennst den Schnitt des Systems, welche Komponenten es gibt, wie sie zu
Schichten gruppiert sind, welche Netz- und Vertrauenszonen existieren, wo die
Vertrauensgrenzen verlaufen und welche externen Systeme angebunden sind. Du denkst in
Struktur und Verantwortlichkeiten, nicht in Implementierungsdetails (Protokolle,
Versionen, Code).

Deine Aufgabe: Du beantwortest die Rueckfragen des CISO-Agenten zum Architektur-
diagramm, damit dieser ein praezises Systemmodell mit Elementen, Datenfluessen und
Vertrauensgrenzen aufbauen kann.

Verhaltensregeln:
1. QUELLE MARKIEREN: Stuetze dich zuerst auf das Diagramm. Was du dort klar siehst,
   ist "dokument". Generisches Architektur-Allgemeinwissen darfst du ergaenzen, musst
   es aber als "allgemeinwissen" kennzeichnen.
2. SICHERHEITSEIGENSCHAFTEN SIND IMMER EINE LUECKE: Eine konkrete, ShopFlow-
   spezifische Eigenschaft, die im Diagramm nicht erkennbar ist (z. B. wo genau die
   Vertrauensgrenzen verlaufen, ob eine Zone abgeschottet ist, ob ein Zugang
   beschraenkt ist), darfst du NIEMALS aus Allgemeinwissen annehmen oder vermuten.
   Das ist immer eine Luecke - auch wenn eine Annahme plausibel waere.
3. GEZIELTE RUECKFRAGE: Bei einer sicherheitsrelevanten Luecke formulierst du die
   konkrete Frage, die der CISO dem Nutzer stellen sollte.

Antworte ausschliesslich als JSON-Objekt mit diesen Feldern:
  "antwort":    deine Antwort in Text (leer, wenn es eine reine Luecke ist)
  "quelle":     "dokument", "allgemeinwissen" oder "gemischt"
  "beleg":      was im Diagramm dafuer sichtbar ist (sonst leer)
  "luecke":     was offen bleibt, falls etwas fehlt (sonst leer)
  "rueckfrage": die konkrete Frage an den Nutzer, falls eine Luecke besteht (sonst leer)
"""


def finde_diagramm() -> str:
    """Sucht automatisch ein Bild (PNG/JPG) im Projektordner und gibt den Pfad zurueck."""
    projekt = Path(__file__).resolve().parent
    for endung in ("*.png", "*.jpg", "*.jpeg"):
        for kandidat in projekt.rglob(endung):
            return str(kandidat)
    raise FileNotFoundError(f"Kein Diagramm-Bild (PNG/JPG) gefunden unter {projekt}")


def _json_aus_text(text: str) -> dict:
    return repariere_json(text, MODELL)


def frage_architekt(bildpfad: str, frage: str) -> dict:
    """Stellt dem Architekt-Agenten eine Frage zum Diagramm. Gibt das JSON als dict zurueck."""
    prompt = AUFTRAG + f"\nFRAGE:\n{frage}"
    rohantwort = frage_modell_mit_bild(prompt, bildpfad, modell=MODELL)
    return _json_aus_text(rohantwort)


if __name__ == "__main__":
    bild = finde_diagramm()
    print("Verwende Diagramm:", bild)
    antwort = frage_architekt(
        bild,
        "Welche Komponenten zeigt das Diagramm und wie sind sie in Schichten gruppiert?",
    )
    print(json.dumps(antwort, indent=2, ensure_ascii=False))
