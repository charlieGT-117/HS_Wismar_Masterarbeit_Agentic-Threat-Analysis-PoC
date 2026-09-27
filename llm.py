"""Modellschnittstelle: Zentralisiert die Kommunikation mit den Sprachmodellen und unterstützt textbasierte Anfragen (frage_modell), 
multimodale Anfragen mit Bild (frage_modell_mit_bild) sowie Anfragen mit integrierter Websuche (frage_modell_websuche).
"""

import os
import re
import json
import time
import base64
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

import metriken


def extrahiere_json(text: str) -> dict:
    """Holt das JSON-Objekt aus einer Modellantwort (entfernt ```-Bloecke,
    schneidet auf die erste { bis letzte } zu)."""
    text = text.strip()
    treffer = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if treffer:
        text = treffer.group(1).strip()
    if not text.startswith("{"):
        start, ende = text.find("{"), text.rfind("}")
        if start != -1 and ende != -1:
            text = text[start:ende + 1]
    return json.loads(text)


def repariere_json(rohtext: str, modell: str = "claude-sonnet-4-6",
                   anbieter: str = "anthropic") -> dict:
    """Parst die Antwort als JSON. Scheitert das (z. B. nicht escapte
    Anfuehrungszeichen im Text), laesst der Code das Modell das JSON EINMAL
    reparieren und parst erneut."""
    try:
        return extrahiere_json(rohtext)
    except Exception:
        print("... JSON ungueltig, fordere Reparatur an ...", flush=True)
        reparatur = frage_modell(
            "Die folgende Antwort sollte ein einzelnes JSON-Objekt sein, ist aber "
            "ungueltig (haeufig: nicht escapte Anfuehrungszeichen oder Zeilenumbrueche "
            "in Zeichenketten). Gib EXAKT dieselben Informationen erneut als striktes, "
            "gueltiges JSON-Objekt aus: Anfuehrungszeichen innerhalb von Texten mit \\\" "
            "escapen, keine echten Zeilenumbrueche in Werten, nichts weglassen. Antworte "
            "ausschliesslich mit dem JSON-Objekt:\n\n" + rohtext,
            anbieter=anbieter, modell=modell, max_tokens=8000)
        return extrahiere_json(reparatur)


def frage_modell_websuche(text: str, modell: str = "claude-sonnet-4-6",
                          max_suchen: int = 5, max_tokens: int = 8000) -> str:
    """Laesst Claude selbst im Internet recherchieren (Web-Such-Werkzeug) und gibt
    die finale Antwort zurueck. Die Antwort enthaelt echte Quell-URLs als Beleg.

    Bei der Websuche entstehen MEHRERE Textbloecke: Zwischen-Narration zwischen den
    Suchen und ganz am Ende die eigentliche Antwort mit dem JSON. Wir nehmen den
    LETZTEN Textblock, der eine geschweifte Klammer enthaelt (die finale Antwort) -
    das Zusammenfuegen aller Bloecke wuerde ungueltiges JSON ergeben.
    """
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=300.0)
    print("... Claude recherchiert im Internet ...", flush=True)
    _t0 = time.perf_counter()
    antwort = client.messages.create(
        model=modell,
        max_tokens=max_tokens,
        tools=[{"type": "web_search_20250305", "name": "web_search", "max_uses": max_suchen}],
        messages=[{"role": "user", "content": text}],
    )
    _it, _ot = metriken.tokens_aus_antwort(antwort)
    metriken.erfasse(modell, _it, _ot, time.perf_counter() - _t0)
    teile = [b.text for b in antwort.content
             if getattr(b, "type", "") == "text" and (b.text or "").strip()]
    if getattr(antwort, "stop_reason", "") == "max_tokens":
        print("... WARNUNG: Antwort wurde durch max_tokens abgeschnitten - "
              "evtl. unvollstaendiges JSON.", flush=True)
    print(f"... Recherche abgeschlossen ({len(teile)} Textbloecke).", flush=True)
    if not teile:
        return ""
    mit_json = [t for t in teile if "{" in t and "}" in t]
    return (mit_json[-1] if mit_json else teile[-1])


# --- Nur Text -------------------------------------------------------------

def frage_modell(text: str, anbieter: str = "anthropic",
                 modell: str = "claude-sonnet-4-6", max_tokens: int = 8000) -> str:
    if anbieter == "anthropic":
        return _frage_anthropic(text, modell, max_tokens)
    elif anbieter == "openai":
        return _frage_openai(text, modell, max_tokens)
    else:
        raise ValueError(f"Unbekannter Anbieter: {anbieter}")


def _frage_anthropic(text: str, modell: str, max_tokens: int) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=300.0)
    print("... Anfrage an Claude gesendet, warte auf Antwort ...", flush=True)
    _t0 = time.perf_counter()
    antwort = client.messages.create(
        model=modell,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": text}],
    )
    _it, _ot = metriken.tokens_aus_antwort(antwort)
    metriken.erfasse(modell, _it, _ot, time.perf_counter() - _t0)
    print("... Antwort erhalten.", flush=True)
    return antwort.content[0].text


def _frage_openai(text: str, modell: str, max_tokens: int) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=120.0)
    _t0 = time.perf_counter()
    antwort = client.chat.completions.create(
        model=modell,
        max_completion_tokens=max_tokens,
        messages=[{"role": "user", "content": text}],
    )
    _it, _ot = metriken.tokens_aus_antwort(antwort)
    metriken.erfasse(modell, _it, _ot, time.perf_counter() - _t0)
    return antwort.choices[0].message.content


# --- Text + Bild (nur Anthropic) ------------------------------------------

def frage_modell_mit_bild(text: str, bildpfad: str,
                          modell: str = "claude-haiku-4-5-20251001",
                          max_tokens: int = 8000) -> str:
    """Schickt Text UND ein Bild an Claude und gibt die Antwort zurueck."""
    import anthropic

    pfad = Path(bildpfad)
    endung = pfad.suffix.lower()
    media_type = "image/png" if endung == ".png" else "image/jpeg"
    rohbytes = pfad.read_bytes()
    if not rohbytes:
        raise ValueError(
            f"Die Bilddatei ist leer (0 Byte): {pfad}. Bitte ein gueltiges, nicht-leeres "
            "PNG/JPG des Architekturdiagramms in den Ordner 'Input/' legen.")
    daten = base64.standard_b64encode(rohbytes).decode("utf-8")

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=300.0)
    print("... Bild + Anfrage an Claude gesendet, warte auf Antwort ...", flush=True)
    _t0 = time.perf_counter()
    antwort = client.messages.create(
        model=modell,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": [
            {"type": "image",
             "source": {"type": "base64", "media_type": media_type, "data": daten}},
            {"type": "text", "text": text},
        ]}],
    )
    _it, _ot = metriken.tokens_aus_antwort(antwort)
    metriken.erfasse(modell, _it, _ot, time.perf_counter() - _t0)
    print("... Antwort erhalten.", flush=True)
    return antwort.content[0].text
